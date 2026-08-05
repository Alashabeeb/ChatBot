import express from 'express';
import cors from 'cors';
import { PORT, OPENSEARCH_URL } from './config/env.js';
import chatRoutes from './routes/chat.routes.js';

const app = express();

app.use(cors());
app.use(express.json());

// Register API Routes
app.use('/api/chat', chatRoutes);

app.listen(PORT, () => {
    console.log(`🚀 AI SOC Proxy Server running on port ${PORT}`);
    console.log(`OpenSearch URL: ${OPENSEARCH_URL}`);
});
