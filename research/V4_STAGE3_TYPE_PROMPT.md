# V4 Stage 3 Type Prompt Development Amendment

Stage 2 development showed that the R order prompt repaired the clean evidence chain in the development set, while the C type prompt did not repair S4 classification. In the R1C0 condition, all four vulnerable development cases reached S3, but only one reached S4. The observed wrong labels followed the object-versus-function boundary:

- BOLA cases involve an actor who may use the business action on an authorized object, but changes another subject's object or a shared read-only object.
- BFLA cases involve an actor who lacks the business action itself, even on their own object, because the action is reserved to a higher role such as administrator, finance, or M.

This amendment keeps the R prompt unchanged and replaces only the C prompt with a two-step rule based on the visible policy. It does not add case identifiers, private truth, target IDs, or reserved cases.

After installation, rerun a fresh V4 development directory before any reserved evaluation. Treat the previous Stage 2 Ollama development output as a development diagnostic, not as final evaluation evidence.
