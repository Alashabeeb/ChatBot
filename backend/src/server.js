// Must stay the first import: exits on missing required config before anything else runs.
import './config/startupCheck.js';
import express from 'express';
import cors from 'cors';
import { PORT, OPENSEARCH_URL } from './config/env.js';
import { initDatabase } from './config/db.js';
import authRoutes from './routes/auth.routes.js';
import sessionRoutes from './routes/session.routes.js';
import chatRoutes from './routes/chat.routes.js';
import queryRoutes from './routes/queries.routes.js';
import { authenticateToken } from './middleware/auth.middleware.js';
import { RunModel } from './models/Run.js';
import { SERVER_INSTANCE_ID } from './observability/instance.js';

// Initialize SQLite Database schema & default admin
initDatabase();

// Runs left 'running' by a previous process can no longer be executing.
console.log(`[Server] Instance ID: ${SERVER_INSTANCE_ID}`);
const interruptedRuns = RunModel.markInterruptedRuns(SERVER_INSTANCE_ID);
if (interruptedRuns.length > 0) {
    console.warn(`[Server] Marked ${interruptedRuns.length} run(s) from a previous server instance as interrupted: ${interruptedRuns.join(', ')}`);
}

const app = express();

app.use(cors());
app.use(express.json({ limit: '500mb' }));
app.use(express.urlencoded({ extended: true, limit: '500mb' }));

// Register API Routes
app.use('/api/auth', authRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/queries', queryRoutes);
app.use('/api/chat', authenticateToken, chatRoutes);

app.listen(PORT, () => {
    console.log(`🚀 AI SOC Proxy Server running on port ${PORT}`);
    console.log(`OpenSearch URL: ${OPENSEARCH_URL}`);
});
