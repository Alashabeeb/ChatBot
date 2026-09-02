import express from 'express';
import cors from 'cors';
import { PORT, OPENSEARCH_URL } from './config/env.js';
import { initDatabase } from './config/db.js';
import authRoutes from './routes/auth.routes.js';
import sessionRoutes from './routes/session.routes.js';
import chatRoutes from './routes/chat.routes.js';
import queryRoutes from './routes/queries.routes.js';
import { authenticateToken } from './middleware/auth.middleware.js';

// Initialize SQLite Database schema & default admin
initDatabase();

const app = express();

app.use(cors());
app.use(express.json());

// Register API Routes
app.use('/api/auth', authRoutes);
app.use('/api/sessions', sessionRoutes);
app.use('/api/queries', queryRoutes);
app.use('/api/chat', authenticateToken, chatRoutes);

app.listen(PORT, () => {
    console.log(`🚀 AI SOC Proxy Server running on port ${PORT}`);
    console.log(`OpenSearch URL: ${OPENSEARCH_URL}`);
});
