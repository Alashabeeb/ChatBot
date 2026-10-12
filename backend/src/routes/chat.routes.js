import { Router } from 'express';
import { handleChat, handleSearchStream } from '../controllers/chat.controller.js';
import { handleChatStream } from '../controllers/assistant.controller.js';
import { handleMessage } from '../controllers/message.controller.js';

const router = Router();

router.post('/', handleChat);              // Search Wazuh: the agent pipeline
router.post('/stream', handleChatStream);   // General chat with the model, streamed
router.post('/search/stream', handleSearchStream);
router.post('/message', handleMessage);   // Any message: the assistant decides chat or search, streamed   // Search Wazuh, streamed (verified text only)

export default router;
