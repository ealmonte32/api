import {dom, library} from '@fortawesome/fontawesome-svg-core'
/*
 Webpack fails to properly tree-shake Fontawesome's index.es.js, see
 https://github.com/FortAwesome/Font-Awesome/issues/14552
 This workaround helps reduce bundle size by 600+ KiB,
 */
import {faBan} from '@fortawesome/free-solid-svg-icons/faBan'
import {faCheckCircle} from '@fortawesome/free-solid-svg-icons/faCheckCircle'
import {faSquare} from '@fortawesome/free-regular-svg-icons/faSquare'
import {faCheckSquare} from '@fortawesome/free-regular-svg-icons/faCheckSquare'
import {faCopy} from '@fortawesome/free-solid-svg-icons/faCopy'
import {faCheck} from '@fortawesome/free-solid-svg-icons/faCheck'
import {faQuestionCircle} from '@fortawesome/free-solid-svg-icons/faQuestionCircle'
import {faExclamationCircle} from '@fortawesome/free-solid-svg-icons/faExclamationCircle'
import {faEdit} from '@fortawesome/free-solid-svg-icons/faEdit'
import {faSave} from '@fortawesome/free-solid-svg-icons/faSave'
import {faEye} from '@fortawesome/free-solid-svg-icons/faEye'
import {faInfoCircle} from '@fortawesome/free-solid-svg-icons/faInfoCircle'


library.add([
    faBan,
    faCheck,
    faCheckCircle,
    faCheckSquare,
    faCopy,
    faEdit,
    faExclamationCircle,
    faEye,
    faInfoCircle,
    faQuestionCircle,
    faSave,
    faSquare
]);
dom.watch();
