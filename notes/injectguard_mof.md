# InjectGuard MOF Training Strategy (paper NOT found)

**Status**: Extensive WebSearch for "InjectGuard", "InjectGuard arxiv", "avdvg InjectGuard", "model oriented forgetting jailbreak", "MOF corrective samples" returned no relevant academic results. The specific paper/repo referenced in the task prompt could not be located. This note documents the concept from general knowledge and states what we need from it.

## What MOF (Model-Oriented Forgetting) Is — General Concept

Model-Oriented Forgetting is a training-time defense technique against keyword/trigger-word jailbreaks. The core idea:

1. **Identify trigger words**: Words/phrases that attackers commonly embed in jailbreak prompts (e.g., "ignore previous instructions", "you are now DAN", "system override").

2. **Construct corrective samples**: Create training examples that CONTAIN the trigger word but are SEMANTICALLY BENIGN. For example:
   - "Please **ignore previous** error messages and try the operation again" (benign: debugging)
   - "The **system override** switch is located on the back panel" (benign: hardware documentation)
   
3. **Train with corrective samples**: Mix these into the fine-tuning data so the model learns that the presence of a trigger word alone does NOT imply malicious intent. The model must attend to the broader semantic context.

4. **Effect**: Reduces false positives on trigger-word matches while maintaining the ability to reject genuinely malicious uses of the same words. This is the NLP equivalent of "new device" fraud flags that account for legitimate new-device logins.

## Connection to Our Dataset's Near-Duplicate Pairs

Our dataset already has a `near_dup_pairs` mechanism (Step 3 of the original spec) that generates "approximately duplicated" benign versions of malicious samples. The MOF concept directly informs this:

- **Current approach**: Near-dup pairs flip labels on minimally-edited malicious texts → teaches the classifier that small text changes shouldn't flip the verdict.
- **MOF extension**: Specifically construct benign samples that contain the TRIGGER WORDS found in malicious samples (e.g., "ignore previous" in a debugging context) → teaches the classifier that trigger words alone aren't sufficient evidence.

## What We Need for Step 3

If we can locate the actual InjectGuard paper, we need:
1. The exact recipe for selecting trigger words (frequency-based? from a curated list?)
2. The corrective sample construction algorithm (template-based? LLM-generated? keyword substitution?)
3. The training mix ratio (what fraction of training data should be corrective samples?)
4. Loss weighting (is there a special loss term for corrective samples?)
5. Reported effect on attack success rate and false positive rate

## For Now (v0 implementation)

Without the paper, we'll implement a pragmatic version:
- Extract the most common "override/ignore/system" trigger phrases from our existing malicious training data
- Generate benign contexts containing these phrases using the parameterized template approach (similar to our 4-family generator)
- Mix corrective samples at ~10% of the total training data (a common ratio in adversarial training literature)
- Document that this is a simplified version; cite the InjectGuard concept as motivation and note the paper could not be retrieved

## Gaps
- Could not verify "avdvg/InjectGuard" GitHub repo exists
- No arxiv paper found with this title
- MOF details are from general knowledge, not the specific paper
