// CSS
import "../scss/app.scss";

// Global
import "./modules/bootstrap";
// import "./modules/dragula";
import "./modules/feather";
import "./modules/font-awesome";
import "./modules/moment";
import "./modules/sidebar";
import "./modules/toastr";
import "./modules/user-agent";

// Charts
import "./modules/chartjs";
// import "./modules/apexcharts";

// Forms
// import "./modules/daterangepicker";
// import "./modules/datetimepicker";
// import "./modules/fullcalendar";
// import "./modules/markdown";
import "./modules/mask";
// import "./modules/quill";
import "./modules/select2";
import "./modules/validation";
// import "./modules/wizard";

// Maps
// import "./modules/vector-maps";

// Tables
import "./modules/datatables";

import hljs from 'highlight.js';
window.hljs = hljs;

window.Tagulous = require('exports-loader?Tagulous!../../staticfiles/tagulous/tagulous.js')
require('exports-loader?window.select23!../../staticfiles/tagulous/adaptor/select2-3.js')