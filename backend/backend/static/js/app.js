// CSS
import "../scss/app.scss";

// Global
import "./modules/bootstrap";
import "./modules/feather";
import "./modules/font-awesome";
import "./modules/moment";
import "./modules/sidebar";
import "./modules/user-agent";

// Charts
import "./modules/chartjs";

// Forms
import "./modules/mask";
import "Select2/select2.js";
import "./modules/validation";

// Tables
import "./modules/datatables";

// Code highlight
import hljs from 'highlight.js';
window.hljs = hljs;

// Tags
window.Tagulous = require('exports-loader?Tagulous!../../staticfiles/tagulous/tagulous.js');
require('exports-loader?window.select23!../../staticfiles/tagulous/adaptor/select2-3.js');

// Copy to clipboard
import * as clipboard from "clipboard-polyfill"
window.copyToClipboard = (text) => clipboard.writeText(text);

import ip from "ip-regex";
window.ip = ip;

require('jquery-confirm');

window.mixpanel = require('mixpanel-browser');