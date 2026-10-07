import { findFatalConfigErrors } from './env.js';

// server.js imports this module first, so the process exits before any other module
// has side effects (creating the database, seeding the admin user, listening on a port).
const errors = findFatalConfigErrors();
if (errors.length > 0) {
    for (const error of errors) {
        console.error(`❌ FATAL CONFIG ERROR: ${error}`);
    }
    console.error('❌ Refusing to start the AI SOC Proxy Server.');
    process.exit(1);
}
