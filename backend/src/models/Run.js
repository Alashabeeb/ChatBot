import db from '../config/db.js';

const toJson = value => (value === undefined || value === null ? null : JSON.stringify(value));
const fromJson = value => (value === null || value === undefined ? null : JSON.parse(value));

/**
 * One row per runAgentWorkflow execution. Inserted as 'running' when the run starts and
 * updated when it completes or fails, so a run that hangs (see F-03) stays visible as 'running'.
 */
export class RunModel {
    static start({ requestId, userId, instanceId, question, startedAt }) {
        db.prepare(`
            INSERT INTO runs (request_id, user_id, instance_id, status, question, started_at)
            VALUES (?, ?, ?, 'running', ?, ?)
        `).run(requestId, userId, instanceId, question, startedAt);
    }

    /**
     * Called once at server startup. Any run still 'running' that belongs to a different instance
     * cannot still be executing: its process is gone. Marks those 'interrupted' so that 'running'
     * only ever means "in progress, or hung, in the live process".
     * Assumes one backend process per database (see FINDINGS F-31).
     */
    static markInterruptedRuns(currentInstanceId) {
        const orphaned = db.prepare(`
            SELECT request_id, instance_id, errors_json FROM runs
            WHERE status = 'running' AND (instance_id IS NULL OR instance_id != ?)
        `).all(currentInstanceId);

        const now = new Date().toISOString();
        const update = db.prepare("UPDATE runs SET status = 'interrupted', errors_json = ? WHERE request_id = ? AND status = 'running'");
        db.transaction(() => {
            for (const row of orphaned) {
                const errors = fromJson(row.errors_json) || [];
                errors.push({
                    stage: 'server',
                    message: `Server instance ${row.instance_id ?? '(unknown)'} stopped before this run finished; marked interrupted by instance ${currentInstanceId} at startup.`,
                    at: now
                });
                update.run(JSON.stringify(errors), row.request_id);
            }
        })();
        return orphaned.map(r => r.request_id);
    }

    static finish(requestId, { status, planner, tools, reportText, timings, errors, modelGenerated, generation, completedAt }) {
        return db.prepare(`
            UPDATE runs
            SET status = ?, planner_json = ?, tools_json = ?, report_text = ?, timings_json = ?,
                errors_json = ?, model_generated = ?, generation_json = ?, completed_at = ?
            WHERE request_id = ?
        `).run(
            status,
            toJson(planner),
            toJson(tools),
            reportText ?? null,
            toJson(timings),
            toJson(errors),
            modelGenerated === null || modelGenerated === undefined ? null : (modelGenerated ? 1 : 0),
            toJson(generation),
            completedAt,
            requestId
        ).changes;
    }

    static findById(requestId) {
        const row = db.prepare('SELECT * FROM runs WHERE request_id = ?').get(requestId);
        if (!row) return null;
        return {
            requestId: row.request_id,
            userId: row.user_id,
            instanceId: row.instance_id,
            status: row.status,
            question: row.question,
            planner: fromJson(row.planner_json),
            tools: fromJson(row.tools_json),
            reportText: row.report_text,
            timings: fromJson(row.timings_json),
            errors: fromJson(row.errors_json),
            modelGenerated: row.model_generated === null ? null : row.model_generated === 1,
            generation: fromJson(row.generation_json),
            startedAt: row.started_at,
            completedAt: row.completed_at
        };
    }

    static belongsToUser(requestId, userId) {
        return Boolean(db.prepare('SELECT 1 FROM runs WHERE request_id = ? AND user_id = ?').get(requestId, userId));
    }
}
