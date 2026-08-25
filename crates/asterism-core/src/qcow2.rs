//! Read-only qcow2 v2/v3 materialisation.
//!
//! This is deliberately narrower than a virtual-disk driver. It accepts the
//! standalone, unencrypted images published by the catalog and
//! writes their active guest-visible bytes to sparse raw. Every input offset,
//! table descriptor and referenced refcount is checked in a complete preflight
//! before the destination is created. Backing files, encryption, external data,
//! zstd compression and extended L2 entries fail at that boundary instead of
//! producing a partial disk; ordinary qcow2 deflate is decoded in pure Rust.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use flate2::read::DeflateDecoder;

const MAGIC: &[u8; 4] = b"QFI\xfb";
const V2_HEADER_LEN: usize = 72;
const V3_HEADER_LEN: usize = 104;
const MAX_CLUSTER_BITS: u32 = 21;
const MAX_L1_BYTES: u64 = 32 * 1024 * 1024;
const MAX_REFCOUNT_TABLE_BYTES: u64 = 8 * 1024 * 1024;
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COPIED: u64 = 1 << 63;
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;
const SPARSE_BLOCK: usize = 4096;

#[derive(Debug)]
struct Header {
    version: u32,
    cluster_bits: u32,
    cluster_size: u64,
    virtual_size: u64,
    l1_size: u32,
    l1_offset: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    refcount_order: u32,
}

#[derive(Debug)]
struct Extent {
    guest: u64,
    len: u64,
    source: ExtentSource,
}

#[derive(Debug, Clone, Copy)]
enum ExtentSource {
    Standard { host: u64 },
    Deflate { host: u64, stored_len: u64 },
}

struct Image {
    source: File,
    header: Header,
    extents: Vec<Extent>,
}

/// Convert a standalone qcow2 v2/v3 image into sparse raw.
///
/// The source is fully preflighted before `destination` is opened. The caller
/// owns staging-name cleanup and durable publication, keeping those policies in
/// the same image-store seam used by downloads and OCI images.
pub(crate) fn materialize(source: &Path, destination: &Path) -> Result<()> {
    let image = Image::open(source)?;
    image.write_sparse(destination)
}

impl Image {
    fn open(path: &Path) -> Result<Self> {
        let mut source =
            File::open(path).with_context(|| format!("opening qcow2 source {}", path.display()))?;
        let file_len = source
            .metadata()
            .with_context(|| format!("reading qcow2 metadata for {}", path.display()))?
            .len();
        let header = Header::read(&mut source, file_len)?;
        let l1_bytes = u64::from(header.l1_size)
            .checked_mul(8)
            .context("qcow2 L1 table size overflow")?;
        checked_region(
            "L1 table",
            header.l1_offset,
            l1_bytes,
            file_len,
            Some(header.cluster_size),
        )?;
        if l1_bytes > MAX_L1_BYTES {
            bail!("qcow2 L1 table is larger than the supported 32 MiB bound");
        }

        let refcount_table_bytes = u64::from(header.refcount_table_clusters)
            .checked_mul(header.cluster_size)
            .context("qcow2 refcount table size overflow")?;
        if refcount_table_bytes == 0 || refcount_table_bytes > MAX_REFCOUNT_TABLE_BYTES {
            bail!("qcow2 refcount table size is outside the supported 1..=8 MiB bound");
        }
        checked_region(
            "refcount table",
            header.refcount_table_offset,
            refcount_table_bytes,
            file_len,
            Some(header.cluster_size),
        )?;

        let l2_entries = header.cluster_size / 8;
        let guest_clusters = header.virtual_size.div_ceil(header.cluster_size);
        let required_l1 = guest_clusters.div_ceil(l2_entries);
        if u64::from(header.l1_size) < required_l1 {
            bail!(
                "qcow2 L1 table has {} entries but the virtual disk needs {required_l1}",
                header.l1_size
            );
        }

        let mut l1_raw = vec![0; usize_len(l1_bytes, "L1 table")?];
        read_exact_at(&mut source, header.l1_offset, &mut l1_raw, "L1 table")?;
        let l1 = be_u64s(&l1_raw);

        let mut refcount_raw = vec![0; usize_len(refcount_table_bytes, "refcount table")?];
        read_exact_at(
            &mut source,
            header.refcount_table_offset,
            &mut refcount_raw,
            "refcount table",
        )?;
        let refcount_table = be_u64s(&refcount_raw);
        let mut refs = Refcounts::new(
            refcount_table,
            header.refcount_order,
            header.cluster_size,
            file_len,
        )?;

        let mut metadata = HashMap::<u64, &'static str>::new();
        mark_region(
            &mut metadata,
            0,
            header.cluster_size,
            header.cluster_size,
            "header",
        )?;
        mark_region(
            &mut metadata,
            header.l1_offset,
            l1_bytes,
            header.cluster_size,
            "L1 table",
        )?;
        mark_region(
            &mut metadata,
            header.refcount_table_offset,
            refcount_table_bytes,
            header.cluster_size,
            "refcount table",
        )?;
        let mut refblocks = HashSet::new();
        for &entry in &refs.table {
            if entry & 0x1ff != 0 {
                bail!("qcow2 refcount table entry has reserved low bits set");
            }
            if entry == 0 {
                continue;
            }
            if entry % header.cluster_size != 0 {
                bail!("qcow2 refcount block is not cluster-aligned");
            }
            checked_region(
                "refcount block",
                entry,
                header.cluster_size,
                file_len,
                Some(header.cluster_size),
            )?;
            if !refblocks.insert(entry) {
                bail!("qcow2 refcount table points at one block more than once");
            }
            mark_region(
                &mut metadata,
                entry,
                header.cluster_size,
                header.cluster_size,
                "refcount block",
            )?;
        }

        for (&cluster, &kind) in &metadata {
            refs.require_allocated(&mut source, cluster * header.cluster_size, kind)?;
        }

        let mut extents = Vec::new();
        let mut data_clusters = HashSet::new();
        let needed_l1 = usize_len(required_l1, "required L1 entry count")?;
        for (l1_index, &entry) in l1.iter().take(needed_l1).enumerate() {
            if entry & !(OFFSET_MASK | COPIED) != 0 {
                bail!("qcow2 L1 entry {l1_index} has reserved bits set");
            }
            let l2_offset = entry & OFFSET_MASK;
            if l2_offset == 0 {
                if entry != 0 {
                    bail!("qcow2 L1 entry {l1_index} has flags without an L2 table");
                }
                continue;
            }
            checked_region(
                "L2 table",
                l2_offset,
                header.cluster_size,
                file_len,
                Some(header.cluster_size),
            )?;
            let l2_cluster = l2_offset / header.cluster_size;
            if data_clusters.contains(&l2_cluster) {
                bail!("qcow2 L2 table overlaps a guest data cluster");
            }
            mark_region(
                &mut metadata,
                l2_offset,
                header.cluster_size,
                header.cluster_size,
                "L2 table",
            )?;
            refs.require_allocated(&mut source, l2_offset, "L2 table")?;

            let mut l2_raw = vec![0; usize_len(header.cluster_size, "L2 table")?];
            read_exact_at(&mut source, l2_offset, &mut l2_raw, "L2 table")?;
            for (l2_index, descriptor) in be_u64s(&l2_raw).into_iter().enumerate() {
                let guest_cluster = (l1_index as u64)
                    .checked_mul(l2_entries)
                    .and_then(|n| n.checked_add(l2_index as u64))
                    .context("qcow2 guest cluster index overflow")?;
                if guest_cluster >= guest_clusters {
                    break;
                }
                let guest = guest_cluster * header.cluster_size;
                let len = (header.virtual_size - guest).min(header.cluster_size);
                if let Some(mapping) = validate_l2(
                    descriptor,
                    header.version,
                    header.cluster_bits,
                    file_len,
                    l1_index,
                    l2_index,
                )? {
                    for host_cluster in mapping.clusters(header.cluster_size) {
                        if let Some(kind) = metadata.get(&host_cluster) {
                            bail!("qcow2 guest data overlaps its {kind}");
                        }
                        data_clusters.insert(host_cluster);
                        refs.require_allocated(
                            &mut source,
                            host_cluster * header.cluster_size,
                            "guest data",
                        )?;
                    }
                    if let ExtentSource::Deflate { host, stored_len } = mapping {
                        // Corrupt compressed data is a preflight failure, not
                        // a half-written raw image.
                        read_deflate(&mut source, host, stored_len, header.cluster_size)?;
                        extents.push(Extent {
                            guest,
                            len,
                            source: ExtentSource::Deflate { host, stored_len },
                        });
                    } else {
                        extents.push(Extent {
                            guest,
                            len,
                            source: mapping,
                        });
                    }
                }
            }
        }

        Ok(Self {
            source,
            header,
            extents,
        })
    }

    fn write_sparse(mut self, destination: &Path) -> Result<()> {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .with_context(|| format!("creating sparse raw image {}", destination.display()))?;
        output
            .set_len(self.header.virtual_size)
            .with_context(|| format!("sizing sparse raw image {}", destination.display()))?;

        let mut block = vec![0; SPARSE_BLOCK];
        for extent in self.extents {
            let inflated = match extent.source {
                ExtentSource::Deflate { host, stored_len } => Some(read_deflate(
                    &mut self.source,
                    host,
                    stored_len,
                    self.header.cluster_size,
                )?),
                ExtentSource::Standard { .. } => None,
            };
            let mut done = 0;
            while done < extent.len {
                let len = (extent.len - done).min(SPARSE_BLOCK as u64) as usize;
                match extent.source {
                    ExtentSource::Standard { host } => read_exact_at(
                        &mut self.source,
                        host + done,
                        &mut block[..len],
                        "guest data cluster",
                    )?,
                    ExtentSource::Deflate { .. } => block[..len].copy_from_slice(
                        &inflated.as_ref().unwrap()[done as usize..done as usize + len],
                    ),
                }
                if block[..len].iter().any(|&byte| byte != 0) {
                    output.seek(SeekFrom::Start(extent.guest + done))?;
                    output.write_all(&block[..len])?;
                }
                done += len as u64;
            }
        }
        output.flush()?;
        Ok(())
    }
}

impl Header {
    fn read(file: &mut File, file_len: u64) -> Result<Self> {
        if file_len < V2_HEADER_LEN as u64 {
            bail!("qcow2 header is truncated");
        }
        let mut bytes = [0u8; 112];
        let read_len = usize::try_from(file_len.min(bytes.len() as u64)).unwrap();
        read_exact_at(file, 0, &mut bytes[..read_len], "qcow2 header")?;
        if &bytes[..4] != MAGIC {
            bail!("not a qcow2 image (bad magic)");
        }
        let version = u32_at(&bytes, 4);
        if !matches!(version, 2 | 3) {
            bail!("unsupported qcow2 version {version}; only v2 and v3 are accepted");
        }
        let backing_offset = u64_at(&bytes, 8);
        let backing_size = u32_at(&bytes, 16);
        if backing_offset != 0 || backing_size != 0 {
            bail!("qcow2 backing files are unsupported; flatten the image before importing it");
        }
        let cluster_bits = u32_at(&bytes, 20);
        if !(9..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
            bail!("qcow2 cluster_bits {cluster_bits} is outside the supported 9..={MAX_CLUSTER_BITS} range");
        }
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = u64_at(&bytes, 24);
        if virtual_size > (1u64 << 56) {
            bail!("qcow2 virtual size exceeds the format's 64 PiB mapping bound");
        }
        let crypt_method = u32_at(&bytes, 32);
        if crypt_method != 0 {
            bail!("encrypted qcow2 images are unsupported; decrypt and flatten the image first");
        }
        let l1_size = u32_at(&bytes, 36);
        let l1_offset = u64_at(&bytes, 40);
        let refcount_table_offset = u64_at(&bytes, 48);
        let refcount_table_clusters = u32_at(&bytes, 56);
        let snapshots = u32_at(&bytes, 60);
        let snapshots_offset = u64_at(&bytes, 64);
        if snapshots != 0 || snapshots_offset != 0 {
            bail!("qcow2 internal snapshots are unsupported; flatten the active image first");
        }

        let refcount_order = if version == 2 {
            4
        } else {
            if file_len < V3_HEADER_LEN as u64 {
                bail!("qcow2 v3 header is truncated");
            }
            let incompatible = u64_at(&bytes, 72);
            if incompatible != 0 {
                let reason = match incompatible.trailing_zeros() {
                    0 => "dirty refcounts",
                    1 => "the corrupt flag",
                    2 => "an external data file",
                    3 => "non-default compression",
                    4 => "extended L2 entries",
                    _ => "an unknown incompatible feature",
                };
                bail!("qcow2 image uses {reason}; refusing before raw output is created");
            }
            let order = u32_at(&bytes, 96);
            if order > 6 {
                bail!("qcow2 refcount_order {order} is larger than 6");
            }
            let header_len = u32_at(&bytes, 100);
            if header_len < V3_HEADER_LEN as u32
                || !header_len.is_multiple_of(8)
                || u64::from(header_len) > cluster_size
                || u64::from(header_len) > file_len
            {
                bail!("qcow2 v3 header_length is malformed or out of bounds");
            }
            if header_len > 104 && bytes[104] != 0 {
                bail!("qcow2 compression type is set without its incompatible feature bit");
            }
            order
        };

        if l1_size != 0 && l1_offset == 0 {
            bail!("qcow2 L1 table has entries but no offset");
        }
        Ok(Self {
            version,
            cluster_bits,
            cluster_size,
            virtual_size,
            l1_size,
            l1_offset,
            refcount_table_offset,
            refcount_table_clusters,
            refcount_order,
        })
    }
}

struct Refcounts {
    table: Vec<u64>,
    blocks: HashMap<usize, Vec<u8>>,
    bits: u32,
    entries_per_block: u64,
    cluster_size: u64,
}

impl Refcounts {
    fn new(table: Vec<u64>, order: u32, cluster_size: u64, _file_len: u64) -> Result<Self> {
        let bits = 1u32 << order;
        let entries_per_block = cluster_size
            .checked_mul(8)
            .and_then(|n| n.checked_div(u64::from(bits)))
            .context("qcow2 refcount geometry overflow")?;
        Ok(Self {
            table,
            blocks: HashMap::new(),
            bits,
            entries_per_block,
            cluster_size,
        })
    }

    fn require_allocated(&mut self, file: &mut File, offset: u64, what: &str) -> Result<()> {
        let cluster = offset / self.cluster_size;
        let table_index = usize_len(cluster / self.entries_per_block, "refcount table index")?;
        let block_index = cluster % self.entries_per_block;
        let Some(&block_offset) = self.table.get(table_index) else {
            bail!("qcow2 {what} lies outside the refcount table's coverage");
        };
        if block_offset == 0 {
            bail!("qcow2 {what} has no allocated refcount block");
        }
        if !self.blocks.contains_key(&table_index) {
            let mut bytes = vec![0; usize_len(self.cluster_size, "refcount block")?];
            read_exact_at(file, block_offset, &mut bytes, "refcount block")?;
            self.blocks.insert(table_index, bytes);
        }
        let value = packed_refcount(
            self.blocks.get(&table_index).unwrap(),
            block_index,
            self.bits,
        )?;
        if value == 0 {
            bail!("qcow2 {what} points at a cluster whose refcount is zero");
        }
        Ok(())
    }
}

fn packed_refcount(block: &[u8], index: u64, bits: u32) -> Result<u64> {
    if bits < 8 {
        let per_byte = 8 / bits;
        let byte = *block
            .get(usize_len(index / u64::from(per_byte), "refcount byte")?)
            .context("qcow2 refcount block index is out of bounds")?;
        let shift = bits * (index as u32 % per_byte);
        return Ok(u64::from((byte >> shift) & ((1u8 << bits) - 1)));
    }
    let width = usize::try_from(bits / 8).unwrap();
    let start = usize_len(index, "refcount index")?
        .checked_mul(width)
        .context("qcow2 refcount block index overflow")?;
    let bytes = block
        .get(start..start + width)
        .context("qcow2 refcount block index is out of bounds")?;
    let mut padded = [0u8; 8];
    padded[8 - width..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(padded))
}

fn validate_l2(
    entry: u64,
    version: u32,
    cluster_bits: u32,
    file_len: u64,
    l1_index: usize,
    l2_index: usize,
) -> Result<Option<ExtentSource>> {
    if entry & COMPRESSED != 0 {
        if entry & COPIED != 0 {
            bail!(
                "qcow2 compressed cluster at L1 {l1_index}, L2 {l2_index} has the copied flag set"
            );
        }
        let size_shift = 62 - (cluster_bits - 8);
        let host_mask = (1u64 << size_shift) - 1;
        let host = entry & host_mask;
        if size_shift > 56 && host >> 56 != 0 {
            bail!("qcow2 compressed cluster offset exceeds the 56-bit host bound");
        }
        let sectors_mask = (1u64 << (62 - size_shift)) - 1;
        let sectors = ((entry >> size_shift) & sectors_mask) + 1;
        let stored_len = sectors
            .checked_mul(512)
            .and_then(|bytes| bytes.checked_sub(host & 511))
            .context("qcow2 compressed cluster length overflow")?;
        checked_region("compressed guest data", host, stored_len, file_len, None)?;
        return Ok(Some(ExtentSource::Deflate { host, stored_len }));
    }
    let cluster_size = 1u64 << cluster_bits;
    let allowed = OFFSET_MASK | COPIED | if version == 3 { ZERO } else { 0 };
    if entry & !allowed != 0 {
        bail!("qcow2 L2 entry at L1 {l1_index}, L2 {l2_index} has reserved bits set");
    }
    let offset = entry & OFFSET_MASK;
    if version == 2 && entry & ZERO != 0 {
        bail!("qcow2 v2 L2 entry uses the v3 zero-cluster flag");
    }
    if entry & ZERO != 0 {
        if offset != 0 || entry & COPIED != 0 {
            bail!("qcow2 preallocated zero clusters are unsupported");
        }
        return Ok(None);
    }
    if offset == 0 {
        if entry != 0 {
            bail!("qcow2 L2 entry has flags without a host cluster");
        }
        return Ok(None);
    }
    checked_region(
        "guest data cluster",
        offset,
        cluster_size,
        file_len,
        Some(cluster_size),
    )?;
    Ok(Some(ExtentSource::Standard { host: offset }))
}

impl ExtentSource {
    fn clusters(&self, cluster_size: u64) -> std::ops::RangeInclusive<u64> {
        let (start, len) = match *self {
            Self::Standard { host } => (host, cluster_size),
            Self::Deflate { host, stored_len } => (host, stored_len),
        };
        (start / cluster_size)..=((start + len - 1) / cluster_size)
    }
}

fn read_deflate(file: &mut File, host: u64, stored_len: u64, cluster_size: u64) -> Result<Vec<u8>> {
    let mut stored = vec![0; usize_len(stored_len, "compressed cluster")?];
    read_exact_at(file, host, &mut stored, "compressed guest data")?;
    let mut decoder = DeflateDecoder::new(stored.as_slice());
    let mut decoded = Vec::with_capacity(usize_len(cluster_size, "guest cluster")?);
    decoder
        .by_ref()
        .take(cluster_size + 1)
        .read_to_end(&mut decoded)
        .context("inflating a qcow2 compressed cluster")?;
    if decoded.len() as u64 != cluster_size {
        bail!(
            "qcow2 compressed cluster expanded to {} bytes instead of {cluster_size}",
            decoded.len()
        );
    }
    Ok(decoded)
}

fn checked_region(
    what: &str,
    offset: u64,
    len: u64,
    file_len: u64,
    alignment: Option<u64>,
) -> Result<()> {
    if let Some(alignment) = alignment {
        if !offset.is_multiple_of(alignment) {
            bail!("qcow2 {what} is not cluster-aligned");
        }
    }
    let end = offset
        .checked_add(len)
        .with_context(|| format!("qcow2 {what} offset overflow"))?;
    if end > file_len {
        bail!("qcow2 {what} extends past the end of the source file");
    }
    Ok(())
}

fn mark_region(
    clusters: &mut HashMap<u64, &'static str>,
    offset: u64,
    len: u64,
    cluster_size: u64,
    kind: &'static str,
) -> Result<()> {
    let first = offset / cluster_size;
    let count = len.div_ceil(cluster_size);
    for cluster in first..first + count {
        if let Some(previous) = clusters.insert(cluster, kind) {
            if previous != kind {
                bail!("qcow2 {kind} overlaps its {previous}");
            }
        }
    }
    Ok(())
}

fn read_exact_at(file: &mut File, offset: u64, bytes: &mut [u8], what: &str) -> Result<()> {
    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("seeking to qcow2 {what}"))?;
    file.read_exact(bytes)
        .with_context(|| format!("reading qcow2 {what}"))
}

fn be_u64s(bytes: &[u8]) -> Vec<u64> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_be_bytes(*chunk))
        .collect()
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

fn usize_len(value: u64, what: &str) -> Result<usize> {
    usize::try_from(value).with_context(|| format!("qcow2 {what} does not fit in memory"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLUSTER: usize = 4096;
    const GUEST_CLUSTERS: usize = 65_536;

    fn fixture(version: u32, payload: &[u8]) -> Vec<u8> {
        // 0 header, 1 L1, 2 refcount table, 3 refcount block, 4 L2,
        // 5 first data cluster, guest cluster 1 is deliberately a hole.
        let mut image = vec![0u8; 6 * CLUSTER];
        image[..4].copy_from_slice(MAGIC);
        put32(&mut image, 4, version);
        put32(&mut image, 20, 12);
        put64(&mut image, 24, (GUEST_CLUSTERS * CLUSTER) as u64);
        put32(
            &mut image,
            36,
            (GUEST_CLUSTERS.div_ceil(CLUSTER / 8)) as u32,
        );
        put64(&mut image, 40, CLUSTER as u64);
        put64(&mut image, 48, (2 * CLUSTER) as u64);
        put32(&mut image, 56, 1);
        put64(&mut image, CLUSTER, (4 * CLUSTER) as u64 | COPIED);
        put64(&mut image, 2 * CLUSTER, (3 * CLUSTER) as u64);
        for cluster in 0..6 {
            put16(&mut image, 3 * CLUSTER + cluster * 2, 1);
        }
        put64(&mut image, 4 * CLUSTER, (5 * CLUSTER) as u64 | COPIED);
        image[5 * CLUSTER..5 * CLUSTER + payload.len()].copy_from_slice(payload);
        if version == 3 {
            put32(&mut image, 96, 4);
            put32(&mut image, 100, 104);
        }
        image
    }

    fn materialize_fixture(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.qcow2");
        let raw = dir.path().join("output.raw");
        std::fs::write(&src, bytes).unwrap();
        materialize(&src, &raw).unwrap();
        (dir, raw)
    }

    #[test]
    fn v2_and_v3_materialize_the_same_sparse_guest_bytes() {
        for version in [2, 3] {
            let payload = b"catalog-image";
            let (_dir, raw) = materialize_fixture(&fixture(version, payload));
            let mut file = File::open(&raw).unwrap();
            let mut actual = vec![0; payload.len()];
            file.read_exact(&mut actual).unwrap();
            assert_eq!(actual, payload);
            file.seek(SeekFrom::End(-4096)).unwrap();
            let mut tail = [1u8; 4096];
            file.read_exact(&mut tail).unwrap();
            assert_eq!(tail, [0; 4096]);
            assert_eq!(
                file.metadata().unwrap().len(),
                (GUEST_CLUSTERS * CLUSTER) as u64
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let allocated = std::fs::metadata(&raw).unwrap().blocks() * 512;
                assert!(
                    allocated < (GUEST_CLUSTERS * CLUSTER) as u64 / 4,
                    "raw output was not sparse: {allocated} allocated bytes"
                );
            }
        }
    }

    #[test]
    fn output_matches_qemu_img_when_the_reference_tool_is_available() {
        if std::process::Command::new("qemu-img")
            .arg("--version")
            .output()
            .map_or(true, |output| !output.status.success())
        {
            return;
        }
        for (version, compat) in [(2, "0.10"), (3, "1.1")] {
            let dir = tempfile::tempdir().unwrap();
            let source_raw = dir.path().join("source.raw");
            let qcow2 = dir.path().join(format!("v{version}.qcow2"));
            let native = dir.path().join(format!("v{version}.native.raw"));
            let reference = dir.path().join(format!("v{version}.qemu.raw"));
            let raw = File::create(&source_raw).unwrap();
            raw.set_len((GUEST_CLUSTERS * CLUSTER) as u64).unwrap();
            drop(raw);
            let mut raw = OpenOptions::new().write(true).open(&source_raw).unwrap();
            raw.seek(SeekFrom::Start(17)).unwrap();
            raw.write_all(b"ubuntu-24.04").unwrap();
            raw.seek(SeekFrom::Start((31 * CLUSTER + 9) as u64))
                .unwrap();
            raw.write_all(b"debian-13").unwrap();
            drop(raw);

            let made = std::process::Command::new("qemu-img")
                .args(["convert", "-c", "-f", "raw", "-O", "qcow2", "-o"])
                .arg(format!("compat={compat}"))
                .arg(&source_raw)
                .arg(&qcow2)
                .status()
                .unwrap();
            assert!(made.success());
            materialize(&qcow2, &native).unwrap();
            let converted = std::process::Command::new("qemu-img")
                .args(["convert", "-f", "qcow2", "-O", "raw", "-S", "4k"])
                .arg(&qcow2)
                .arg(&reference)
                .status()
                .unwrap();
            assert!(converted.success());
            assert_files_equal(&native, &reference);
        }
    }

    #[test]
    fn unsupported_features_fail_before_creating_output() {
        let cases: &[(usize, u64, &str)] = &[
            (8, CLUSTER as u64, "backing"),
            (32, 1, "encrypted"),
            (72, 1 << 4, "extended L2"),
        ];
        for &(offset, value, message) in cases {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("source.qcow2");
            let raw = dir.path().join("output.raw");
            let mut bytes = fixture(3, b"data");
            if offset == 32 {
                put32(&mut bytes, offset, value as u32);
            } else {
                put64(&mut bytes, offset, value);
                if offset == 8 {
                    put32(&mut bytes, 16, 4);
                }
            }
            std::fs::write(&src, bytes).unwrap();
            let error = format!("{:#}", materialize(&src, &raw).unwrap_err());
            assert!(error.contains(message), "{error}");
            assert!(!raw.exists(), "unsupported input created raw output");
        }
    }

    #[test]
    fn compressed_and_malformed_mappings_fail_before_creating_output() {
        let mut compressed = fixture(3, b"data");
        put64(
            &mut compressed,
            4 * CLUSTER,
            COMPRESSED | (5 * CLUSTER) as u64,
        );
        let mut out_of_bounds = fixture(3, b"data");
        put64(
            &mut out_of_bounds,
            4 * CLUSTER,
            (99 * CLUSTER) as u64 | COPIED,
        );
        let mut zero_refcount = fixture(3, b"data");
        put16(&mut zero_refcount, 3 * CLUSTER + 5 * 2, 0);

        for (bytes, message) in [
            (compressed, "compressed cluster"),
            (out_of_bounds, "past the end"),
            (zero_refcount, "refcount is zero"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let src = dir.path().join("source.qcow2");
            let raw = dir.path().join("output.raw");
            std::fs::write(&src, bytes).unwrap();
            let error = format!("{:#}", materialize(&src, &raw).unwrap_err());
            assert!(error.contains(message), "{error}");
            assert!(!raw.exists());
        }
    }

    #[test]
    fn an_existing_part_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("source.qcow2");
        let raw = dir.path().join("output.raw");
        std::fs::write(&src, fixture(3, b"data")).unwrap();
        std::fs::write(&raw, b"old partial bytes").unwrap();
        let error = format!("{:#}", materialize(&src, &raw).unwrap_err());
        assert!(error.contains("creating sparse raw image"), "{error}");
        assert_eq!(std::fs::read(raw).unwrap(), b"old partial bytes");
    }

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    }

    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    }

    fn assert_files_equal(left: &Path, right: &Path) {
        let mut left = File::open(left).unwrap();
        let mut right = File::open(right).unwrap();
        assert_eq!(
            left.metadata().unwrap().len(),
            right.metadata().unwrap().len()
        );
        let mut a = [0u8; 64 * 1024];
        let mut b = [0u8; 64 * 1024];
        loop {
            let read = left.read(&mut a).unwrap();
            right.read_exact(&mut b[..read]).unwrap();
            assert_eq!(a[..read], b[..read]);
            if read == 0 {
                break;
            }
        }
    }
}
