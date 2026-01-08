export interface Finding {
    id: string;
    file_path: string;
    line_number: number;
    end_line_number: number | null;
    column: number | null;
    severity: "critical" | "high" | "medium" | "low" | "info";
    category: string;
    message: string;
    suggestion: string;
    agent_name: string;
    rule_id: string | null;
    code_snippet: string | null;
    owasp_category: string | null;
    confidence: number;
}

export interface ReviewResult {
    id: string;
    findings: Finding[];
    summary: string;
    timestamp: string;
    overall_score: number;
    status: string;
    files_analyzed: number;
    total_lines: number;
    execution_time: number;
    agent_summaries: Record<string, string>;
}

const API_BASE_URL = 'http://localhost:8000';

export async function reviewCode(code: string, language: string = 'python'): Promise<ReviewResult> {
    const response = await fetch(`${API_BASE_URL}/api/v1/review/code`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            code,
            file_path: 'snippet.py', // Default for snippets
            language,
        }),
    });

    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || 'Failed to review code');
    }

    return response.json();
}
