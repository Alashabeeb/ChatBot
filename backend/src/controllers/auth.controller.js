import jwt from 'jsonwebtoken';
import { UserModel } from '../models/User.js';

const publicUser = user => ({
    id: user.id,
    username: user.username,
    role: user.role,
    created_at: user.created_at,
    mustChangePassword: user.must_change_password === 1
});
import { JWT_SECRET } from '../config/env.js';

export async function login(req, res) {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                type: 'error',
                error: 'Username and password are required.'
            });
        }

        const user = UserModel.findByUsername(username);
        if (!user) {
            return res.status(401).json({
                type: 'error',
                error: 'Invalid username or password.'
            });
        }

        const isValidPassword = UserModel.verifyPassword(password, user.password_hash);
        if (!isValidPassword) {
            return res.status(401).json({
                type: 'error',
                error: 'Invalid username or password.'
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        return res.json({
            success: true,
            token,
            user: publicUser(user)
        });
    } catch (error) {
        console.error('[Auth Controller Error - Login]:', error.message);
        return res.status(500).json({
            type: 'error',
            error: 'Internal authentication error.'
        });
    }
}

export async function getMe(req, res) {
    try {
        const user = UserModel.findById(req.user.id);
        if (!user) {
            return res.status(404).json({
                type: 'error',
                error: 'User not found.'
            });
        }

        return res.json({
            success: true,
            user: publicUser(user)
        });
    } catch (error) {
        return res.status(500).json({
            type: 'error',
            error: error.message
        });
    }
}

export async function changePassword(req, res) {
    try {
        const { currentPassword, newPassword } = req.body ?? {};
        UserModel.changePassword(req.user.id, currentPassword, newPassword);
        return res.json({ success: true, user: publicUser(UserModel.findById(req.user.id)) });
    } catch (error) {
        return res.status(error.status || 500).json({ type: 'error', error: error.message });
    }
}

export async function listUsers(req, res) {
    try {
        const users = UserModel.listAll();
        return res.json({
            success: true,
            users
        });
    } catch (error) {
        return res.status(500).json({
            type: 'error',
            error: error.message
        });
    }
}

export async function createUser(req, res) {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                type: 'error',
                error: 'Username and password are required.'
            });
        }

        const newUser = UserModel.create({
            username,
            password,
            role: role === 'admin' ? 'admin' : 'user'
        });

        return res.status(201).json({
            success: true,
            user: newUser
        });
    } catch (error) {
        return res.status(400).json({
            type: 'error',
            error: error.message
        });
    }
}

export async function deleteUser(req, res) {
    try {
        const { id } = req.params;
        const result = UserModel.delete(id, req.user.id);
        return res.json({
            success: true,
            message: `User '${result.deletedUsername}' has been successfully deleted.`
        });
    } catch (error) {
        return res.status(400).json({
            type: 'error',
            error: error.message
        });
    }
}
