// Cascade order is load-bearing:
//   1. Astryx reset       (@layer reset)
//   2. the Asterism theme (@layer astryx-theme) — built by `npm run theme`
//      from ../../site/src/theme/asterism.ts, the same module the site
//      compiles, so one file defines the palette for both surfaces
//   3. controls.css       — the control skin both windows are built from
//   4. dialog.css         — the New Instance dialog's own layout
//   5. shell.css          — the main window's own layout
//
// `@astryxdesign/core/astryx.css` is deliberately absent. It is 140 KB of
// component styling for components these windows do not use; see the note
// at the top of controls.css for why they take the theme and leave the
// components.
import '@astryxdesign/core/reset.css';
import './theme/asterism.theme.css';
import './controls.css';
import './dialog.css';
import './shell.css';

import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';

import {windowLabel} from './bridge';
import {NewInstance} from './NewInstance';
import {Shell} from './Shell';

const root = document.getElementById('root');
if (!root) {
  throw new Error('index.html has no #root to mount in');
}

// One bundle, two windows. Which one this page is is a fact about the window
// it was loaded into, so the page asks rather than being told: two entry
// points would be two builds, two CSPs and two things to keep in step.
const main = windowLabel() === 'main';
document.title = main ? 'Asterism' : 'New Instance';

createRoot(root).render(<StrictMode>{main ? <Shell /> : <NewInstance />}</StrictMode>);
