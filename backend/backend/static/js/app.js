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
import "./modules/select2";
import "./modules/validation";

// Tables
import "./modules/datatables";

// Code highlight
import hljs from 'highlight.js';
window.hljs = hljs;

// Tags
window.Tagulous = require('exports-loader?Tagulous!../../staticfiles/tagulous/tagulous.js')
require('exports-loader?window.select23!../../staticfiles/tagulous/adaptor/select2-3.js')

// Copy to clipboard
import * as clipboard from "clipboard-polyfill"
window.copyToClipboard = function(text) {
    return clipboard.writeText(text);
}