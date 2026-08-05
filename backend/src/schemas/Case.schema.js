export const CaseSchema = {
    type: "object",
    properties: {
        caseId: { type: "string" },
        title: { type: "string" },
        status: { type: "string", enum: ["open", "closed", "escalated"] },
        severity: { type: "string" },
        evidenceIds: { type: "array", items: { type: "string" } },
        analystNotes: { type: "string" }
    },
    required: ["caseId", "title", "status"]
};
