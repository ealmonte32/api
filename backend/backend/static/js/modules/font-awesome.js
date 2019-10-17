import { library, dom } from '@fortawesome/fontawesome-svg-core'
import {fas,
    faCopy, faCheck, faQuestionCircle, faExclamationCircle, faEdit,
    faSave, faEye, faInfoCircle
} from '@fortawesome/free-solid-svg-icons'
import {far, faSquare, faCheckSquare} from '@fortawesome/free-regular-svg-icons'

library.add(far, [faSquare, faCheckSquare]);
library.add(fas, [faCopy, faCheck, faQuestionCircle, faExclamationCircle, faEdit,
    faSave, faEye, faInfoCircle]);
dom.watch();
