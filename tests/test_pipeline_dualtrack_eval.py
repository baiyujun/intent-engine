from tier1.pipeline_dualtrack import pipeline_eval


class _FakePipeline:
    def __init__(self):
        self._results = iter(
            [
                {
                    "final_decision": "defer",
                    "tier1_prob": 0.8,
                    "tier0_final": "benign",
                },
                {
                    "final_decision": "allow",
                    "tier1_prob": 0.1,
                    "tier0_final": "benign",
                },
            ]
        )

    def run(self, _record):
        return next(self._results)


def test_pipeline_eval_counts_defer_as_review_flagged_not_allow():
    records = [
        {"label": {"is_malicious": True}},
        {"label": {"is_malicious": False}},
    ]

    result = pipeline_eval(_FakePipeline(), records, "test")

    assert result["Recall"] == 1.0
    assert result["TP"] == 1
    assert result["defer"] == 1
    assert result["allow"] == 1
