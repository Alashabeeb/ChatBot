import { Router } from 'express';
import { handleChat } from '../controllers/chat.controller.js';
import { handleChatStream } from '../controllers/assistant.controller.js';

const router = Router();

router.post('/', handleChat);              // Search Wazuh: the agent pipeline
router.post('/stream', handleChatStream);   // General chat with the model, streamed

export default router;
