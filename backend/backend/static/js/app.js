// CSS
import "../scss/app.scss";

// Global
import "bootstrap";
import "./modules/font-awesome";
import "./modules/sidebar";
import "./modules/user-agent";

// Forms
import "./modules/mask";
import "Select2/select2.js";
import "./modules/validation";

// Tables
import "./modules/datatables";

// Code highlight
import hljs from 'highlight.js/lib/highlight';
import bash from 'highlight.js/lib/languages/bash';
hljs.registerLanguage('bash', bash);


window.hljs = hljs;

// Tags
window.Tagulous = require('exports-loader?Tagulous!../../staticfiles/tagulous/tagulous.js');
require('exports-loader?window.select23!../../staticfiles/tagulous/adaptor/select2-3.js');

// Copy to clipboard
import * as clipboard from "clipboard-polyfill"
window.copyToClipboard = (text) => clipboard.writeText(text);

import ip from "ip-regex";
window.ip = ip;

import 'jquery-confirm';

window.mixpanel = require('mixpanel-browser');

import Shepherd from 'shepherd.js'
window.Shepherd = Shepherd;

import feather from "feather-icons";
window.feather = feather;