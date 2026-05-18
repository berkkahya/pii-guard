# PII_detection

This is a humble proof-of-concept (PoC) project designed to prevent sharing sensitive information (PII) with Large Language Models. 
It acts as a middleware. Before a prompt is sent to the LLM, it scans the text. If sensitive data is found, the request is blocked and logged.


To reduce false positives, it uses algorithmic validation rather than just basic regex:
*   **Turkish National ID (TCKN):** Validated using the Mod10 algorithm.
*   **Credit Cards (Visa/Mastercard):** Validated using the Luhn algorithm.
*   **Contact Info:** Basic email and phone number detection.



