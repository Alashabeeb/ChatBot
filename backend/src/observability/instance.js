import { randomUUID } from 'crypto';

/**
 * Identifies this server process. Every run row records the instance that executed it, so a row
 * left at 'running' by a previous process (restart, crash) can be told apart from a live hang.
 */
export const SERVER_INSTANCE_ID = randomUUID();
