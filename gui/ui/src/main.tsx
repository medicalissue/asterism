// Astryx owns the reset, component primitives, and generated token layer.
// app.css is the single product-layout layer shared by the control center
// and the spacious New Instance flow.
import '@astryxdesign/core/reset.css';
import '@astryxdesign/core/astryx.css';
import './theme/asterism.theme.css';
import './app.css';

import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {Theme} from '@astryxdesign/core/theme';

import {windowLabel} from './bridge';
import {NewInstance} from './NewInstance';
import {Shell} from './Shell';
import {asterismTheme} from './theme/asterism.js';

const root = document.getElementById('root');
if (!root) {
  throw new Error('index.html has no #root to mount in');
}

// One bundle, two windows. Which one this page is is a fact about the window
// it was loaded into, so the page asks rather than being told: two entry
// points would be two builds, two CSPs and two things to keep in step.
const main = windowLabel() === 'main';
document.title = main ? 'Asterism' : 'New Instance';

createRoot(root).render(
  <StrictMode>
    <Theme theme={asterismTheme}>{main ? <Shell /> : <NewInstance />}</Theme>
  </StrictMode>,
);
