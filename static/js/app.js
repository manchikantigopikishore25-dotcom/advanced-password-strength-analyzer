/**
 * Advanced Password Strength Analyzer and Security Recommendation System
 * Client-Side Application Controller
 *
 * Privacy Guarantees:
 * - All analysis happens in memory; no passwords stored locally (no localStorage/cookies).
 * - Safe telemetry is fetched dynamically from server memory.
 */

document.addEventListener("DOMContentLoaded", () => {
    // -----------------------------------------------------------------------
    // DOM Element References
    // -----------------------------------------------------------------------
    const passwordInput = document.getElementById("password-input");
    const toggleVisibilityBtn = document.getElementById("toggle-visibility-btn");
    const eyeIcon = document.getElementById("eye-icon");
    const analyzeBtn = document.getElementById("analyze-btn");
    const clearBtn = document.getElementById("clear-btn");
    const charCounter = document.getElementById("char-counter");
    const quickAlertBox = document.getElementById("quick-alert-box");

    // Score & Meter Elements
    const scoreValue = document.getElementById("score-value");
    const strengthBadge = document.getElementById("strength-badge");
    const scoreReasonsList = document.getElementById("score-reasons-list");
    const meterSegments = [
        document.getElementById("meter-segment-1"),
        document.getElementById("meter-segment-2"),
        document.getElementById("meter-segment-3"),
        document.getElementById("meter-segment-4"),
        document.getElementById("meter-segment-5")
    ];

    // Characteristics Elements
    const valLength = document.getElementById("val-length");
    const valUpper = document.getElementById("val-upper");
    const valLower = document.getElementById("val-lower");
    const valDigits = document.getElementById("val-digits");
    const valSymbols = document.getElementById("val-symbols");
    const valEntropy = document.getElementById("val-entropy");
    const valEffEntropy = document.getElementById("val-eff-entropy");
    const valBlocklist = document.getElementById("val-blocklist");
    const valRepeats = document.getElementById("val-repeats");
    const valSequences = document.getElementById("val-sequences");
    const valKeyboard = document.getElementById("val-keyboard");
    const valDictionary = document.getElementById("val-dictionary");

    const chipLength = document.getElementById("metric-length");
    const chipUpper = document.getElementById("metric-upper");
    const chipLower = document.getElementById("metric-lower");
    const chipDigits = document.getElementById("metric-digits");
    const chipSymbols = document.getElementById("metric-symbols");
    const chipBlocklist = document.getElementById("metric-blocklist");
    const chipRepeats = document.getElementById("metric-repeats");
    const chipSequences = document.getElementById("metric-sequences");
    const chipKeyboard = document.getElementById("metric-keyboard");
    const chipDictionary = document.getElementById("metric-dictionary");

    // Crack Times Elements
    const crackOnlineThrottled = document.getElementById("crack-online-throttled");
    const crackOnlineUnthrottled = document.getElementById("crack-online-unthrottled");
    const crackOfflineSlow = document.getElementById("crack-offline-slow");
    const crackOfflineFast = document.getElementById("crack-offline-fast");

    // zxcvbn Elements
    const zxScoreVal = document.getElementById("zx-score-val");
    const zxGuessesVal = document.getElementById("zx-guesses-val");
    const zxWarningVal = document.getElementById("zx-warning-val");

    // Recommendations Elements
    const detailedFindingsList = document.getElementById("detailed-findings-list");
    const recommendationsList = document.getElementById("recommendations-list");

    // Generator Elements
    const tabModeRandom = document.getElementById("tab-mode-random");
    const tabModePassphrase = document.getElementById("tab-mode-passphrase");
    const controlsRandom = document.getElementById("controls-random");
    const controlsPassphrase = document.getElementById("controls-passphrase");

    const lengthSlider = document.getElementById("length-slider");
    const sliderLengthVal = document.getElementById("slider-length-val");
    const chkUpper = document.getElementById("chk-upper");
    const chkLower = document.getElementById("chk-lower");
    const chkDigits = document.getElementById("chk-digits");
    const chkSymbols = document.getElementById("chk-symbols");
    const chkAmbiguous = document.getElementById("chk-ambiguous");

    const wordsSlider = document.getElementById("words-slider");
    const sliderWordsVal = document.getElementById("slider-words-val");
    const passphraseSep = document.getElementById("passphrase-sep");
    const chkPassCapitalize = document.getElementById("chk-pass-capitalize");
    const chkPassNumber = document.getElementById("chk-pass-number");

    const generatedPasswordText = document.getElementById("generated-password-text");
    const generateSubmitBtn = document.getElementById("generate-submit-btn");
    const copyBtn = document.getElementById("copy-btn");
    const testGeneratedBtn = document.getElementById("test-generated-btn");

    // Telemetry Elements
    const telemetryTableBody = document.getElementById("telemetry-table-body");
    const clearHistoryBtn = document.getElementById("clear-history-btn");
    const statsTotal = document.getElementById("stats-total");
    const statsAvg = document.getElementById("stats-avg");
    const statsStrongPct = document.getElementById("stats-strong-pct");

    let currentGenMode = "random";
    let debounceTimer = null;

    // -----------------------------------------------------------------------
    // Toast Notification System
    // -----------------------------------------------------------------------
    function showToast(message, type = "info") {
        const container = document.getElementById("toast-container");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="16" x2="12" y2="12"></line>
                <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
            <span>${message}</span>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(15px)";
            setTimeout(() => toast.remove(), 250);
        }, 3000);
    }

    // -----------------------------------------------------------------------
    // Visibility Toggle (Show / Hide Password)
    // -----------------------------------------------------------------------
    toggleVisibilityBtn.addEventListener("click", () => {
        const isPassword = passwordInput.getAttribute("type") === "password";
        passwordInput.setAttribute("type", isPassword ? "text" : "password");

        // Toggle SVG icon
        if (isPassword) {
            eyeIcon.innerHTML = `
                <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
                <line x1="1" y1="1" x2="23" y2="23"></line>
            `;
            toggleVisibilityBtn.setAttribute("title", "Hide password text");
        } else {
            eyeIcon.innerHTML = `
                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                <circle cx="12" cy="12" r="3"></circle>
            `;
            toggleVisibilityBtn.setAttribute("title", "Show password text");
        }
    });

    // -----------------------------------------------------------------------
    // Password Input Live Debounce & Character Count
    // -----------------------------------------------------------------------
    passwordInput.addEventListener("input", () => {
        const pwd = passwordInput.value;
        charCounter.textContent = pwd.length;

        // Debounced auto-analysis
        clearTimeout(debounceTimer);
        if (pwd.length === 0) {
            resetDashboard();
        } else {
            debounceTimer = setTimeout(() => {
                performAnalysis(pwd);
            }, 250);
        }
    });

    analyzeBtn.addEventListener("click", () => {
        const pwd = passwordInput.value;
        if (!pwd) {
            showToast("Please enter a password to analyze.", "warning");
            passwordInput.focus();
            return;
        }
        performAnalysis(pwd);
    });

    clearBtn.addEventListener("click", () => {
        passwordInput.value = "";
        charCounter.textContent = "0";
        resetDashboard();
        passwordInput.focus();
    });

    // -----------------------------------------------------------------------
    // Core API Analysis Function
    // -----------------------------------------------------------------------
    async function performAnalysis(password) {
        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ password: password })
            });

            if (!response.ok) {
                const errData = await response.json();
                showToast(errData.error || "Analysis failed.", "danger");
                return;
            }

            const data = await response.json();
            renderAnalysisResults(data);
            refreshTelemetry();

        } catch (error) {
            console.error("Analysis network error:", error);
            showToast("Network error communicating with analysis service.", "danger");
        }
    }

    // -----------------------------------------------------------------------
    // Render Analysis Data into Dashboard
    // -----------------------------------------------------------------------
    function renderAnalysisResults(data) {
        // 1. Score & Classification Badge
        const score = data.score || 0;
        const strength = data.strength || "Very Weak";

        scoreValue.textContent = score;
        strengthBadge.textContent = strength;
        strengthBadge.className = "strength-badge";

        // Segment colors and classes
        resetMeterSegments();
        if (strength === "Very Weak") {
            strengthBadge.classList.add("badge-very-weak");
            meterSegments[0].style.backgroundColor = "var(--color-very-weak)";
            meterSegments[0].style.boxShadow = "0 0 8px var(--color-very-weak)";
        } else if (strength === "Weak") {
            strengthBadge.classList.add("badge-weak");
            meterSegments[0].style.backgroundColor = "var(--color-weak)";
            meterSegments[1].style.backgroundColor = "var(--color-weak)";
            meterSegments[1].style.boxShadow = "0 0 8px var(--color-weak)";
        } else if (strength === "Moderate") {
            strengthBadge.classList.add("badge-moderate");
            meterSegments[0].style.backgroundColor = "var(--color-moderate)";
            meterSegments[1].style.backgroundColor = "var(--color-moderate)";
            meterSegments[2].style.backgroundColor = "var(--color-moderate)";
            meterSegments[2].style.boxShadow = "0 0 8px var(--color-moderate)";
        } else if (strength === "Strong") {
            strengthBadge.classList.add("badge-strong");
            meterSegments[0].style.backgroundColor = "var(--color-strong)";
            meterSegments[1].style.backgroundColor = "var(--color-strong)";
            meterSegments[2].style.backgroundColor = "var(--color-strong)";
            meterSegments[3].style.backgroundColor = "var(--color-strong)";
            meterSegments[3].style.boxShadow = "0 0 8px var(--color-strong)";
        } else if (strength === "Very Strong") {
            strengthBadge.classList.add("badge-very-strong");
            meterSegments.forEach(seg => {
                seg.style.backgroundColor = "var(--color-very-strong)";
                seg.style.boxShadow = "0 0 8px var(--color-very-strong)";
            });
        }

        // Quick Alert Box
        if (data.is_common_password) {
            quickAlertBox.className = "alert-box alert-danger";
            quickAlertBox.innerHTML = `
                <strong>⚠️ Breached Password Warning:</strong> This password matches commonly leaked public dictionaries and is vulnerable to immediate credential stuffing.
            `;
            quickAlertBox.classList.remove("alert-hidden");
        } else if (score >= 80) {
            quickAlertBox.className = "alert-box alert-success";
            quickAlertBox.innerHTML = `
                <strong>✅ Excellent Security:</strong> High effective entropy with strong resistance against automated dictionary and GPU brute-force attacks.
            `;
            quickAlertBox.classList.remove("alert-hidden");
        } else {
            quickAlertBox.classList.add("alert-hidden");
        }

        // 2. Score Reasons
        scoreReasonsList.innerHTML = "";
        const reasons = data.score_explanations || [];
        if (reasons.length === 0) {
            scoreReasonsList.innerHTML = `<li class="reason-placeholder">No penalties or bonuses recorded.</li>`;
        } else {
            reasons.forEach(r => {
                const li = document.createElement("li");
                li.textContent = r;
                scoreReasonsList.appendChild(li);
            });
        }

        // 3. Granular Characteristics Chips
        valLength.textContent = `${data.length} chars`;
        chipLength.className = `metric-chip ${data.length >= 14 ? 'valid' : (data.length >= 8 ? 'warning' : 'invalid')}`;

        valUpper.textContent = data.has_uppercase ? `Yes (${data.uppercase_count})` : "Missing";
        chipUpper.className = `metric-chip ${data.has_uppercase ? 'valid' : 'invalid'}`;

        valLower.textContent = data.has_lowercase ? `Yes (${data.lowercase_count})` : "Missing";
        chipLower.className = `metric-chip ${data.has_lowercase ? 'valid' : 'invalid'}`;

        valDigits.textContent = data.has_number ? `Yes (${data.number_count})` : "Missing";
        chipDigits.className = `metric-chip ${data.has_number ? 'valid' : 'invalid'}`;

        valSymbols.textContent = data.has_special ? `Yes (${data.special_count})` : "Missing";
        chipSymbols.className = `metric-chip ${data.has_special ? 'valid' : 'invalid'}`;

        valEntropy.textContent = `${data.entropy_bits} bits`;
        valEffEntropy.textContent = `${data.effective_entropy_bits} bits`;

        valBlocklist.textContent = data.is_common_password ? "Match Detected!" : "Passed (Safe)";
        chipBlocklist.className = `metric-chip ${data.is_common_password ? 'invalid' : 'valid'}`;

        const patterns = data.patterns || {};
        valRepeats.textContent = patterns.has_repeated_chars ? `Run: ${patterns.max_consecutive_run}` : "None";
        chipRepeats.className = `metric-chip ${patterns.has_repeated_chars ? 'invalid' : 'valid'}`;

        valSequences.textContent = patterns.has_sequence ? `Found (${patterns.sequences.length})` : "None";
        chipSequences.className = `metric-chip ${patterns.has_sequence ? 'warning' : 'valid'}`;

        valKeyboard.textContent = patterns.has_keyboard_walk ? `Found (${patterns.keyboard_walks.length})` : "None";
        chipKeyboard.className = `metric-chip ${patterns.has_keyboard_walk ? 'warning' : 'valid'}`;

        valDictionary.textContent = patterns.has_dictionary_word ? `Found (${patterns.dictionary_words.join(', ')})` : "None";
        chipDictionary.className = `metric-chip ${patterns.has_dictionary_word ? 'warning' : 'valid'}`;

        // 4. Crack Times
        const crack = data.crack_times || {};
        crackOnlineThrottled.textContent = crack.online_throttled || "—";
        crackOnlineUnthrottled.textContent = crack.online_unthrottled || "—";
        crackOfflineSlow.textContent = crack.offline_slow_hash || "—";
        crackOfflineFast.textContent = crack.offline_fast_hash || "—";

        // 5. zxcvbn Telemetry
        const zx = data.zxcvbn || {};
        if (zx.score !== undefined) {
            zxScoreVal.textContent = `${zx.score} / 4`;
            zxGuessesVal.textContent = zx.guesses_log10 ? `10^${zx.guesses_log10}` : "—";
            zxWarningVal.textContent = zx.feedback_warning || "No pattern warnings.";
        }

        // 6. Detailed Categorized Findings
        detailedFindingsList.innerHTML = "";
        const findings = data.detailed_findings || [];
        findings.forEach(f => {
            const card = document.createElement("div");
            card.className = `finding-card severity-${f.severity}`;
            card.innerHTML = `
                <div class="finding-header">
                    <span class="finding-title">${f.title}</span>
                    <span class="finding-tag">${f.category}</span>
                </div>
                <p class="finding-desc">${f.description}</p>
            `;
            detailedFindingsList.appendChild(card);
        });

        // 7. Actionable Recommendations
        recommendationsList.innerHTML = "";
        const recs = data.recommendations || [];
        if (recs.length === 0) {
            recommendationsList.innerHTML = `<li class="rec-item-placeholder">No security improvements required. Password demonstrates exceptional strength!</li>`;
        } else {
            recs.forEach(rec => {
                const li = document.createElement("li");
                li.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 11 12 14 22 4"></polyline>
                        <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                    </svg>
                    <span>${rec}</span>
                `;
                recommendationsList.appendChild(li);
            });
        }
    }

    function resetMeterSegments() {
        meterSegments.forEach(seg => {
            seg.style.backgroundColor = "#1e293b";
            seg.style.boxShadow = "none";
        });
    }

    function resetDashboard() {
        scoreValue.textContent = "0";
        strengthBadge.textContent = "Awaiting Input";
        strengthBadge.className = "strength-badge badge-neutral";
        resetMeterSegments();
        quickAlertBox.classList.add("alert-hidden");

        scoreReasonsList.innerHTML = `<li class="reason-placeholder">Enter a password above to view detailed score rationale and deductions.</li>`;

        valLength.textContent = "0 chars";
        valUpper.textContent = "None";
        valLower.textContent = "None";
        valDigits.textContent = "None";
        valSymbols.textContent = "None";
        valEntropy.textContent = "0.0 bits";
        valEffEntropy.textContent = "0.0 bits";
        valBlocklist.textContent = "Not checked";
        valRepeats.textContent = "None";
        valSequences.textContent = "None";
        valKeyboard.textContent = "None";
        valDictionary.textContent = "None";

        document.querySelectorAll(".metric-chip").forEach(chip => {
            chip.className = "metric-chip";
        });

        crackOnlineThrottled.textContent = "—";
        crackOnlineUnthrottled.textContent = "—";
        crackOfflineSlow.textContent = "—";
        crackOfflineFast.textContent = "—";

        zxScoreVal.textContent = "— / 4";
        zxGuessesVal.textContent = "—";
        zxWarningVal.textContent = "None";

        detailedFindingsList.innerHTML = "";
        recommendationsList.innerHTML = `<li class="rec-item-placeholder">Analysis recommendations will appear here automatically.</li>`;
    }

    // -----------------------------------------------------------------------
    // Password Generator Logic
    // -----------------------------------------------------------------------
    tabModeRandom.addEventListener("click", () => {
        currentGenMode = "random";
        tabModeRandom.classList.add("active");
        tabModePassphrase.classList.remove("active");
        controlsRandom.classList.remove("panel-hidden");
        controlsPassphrase.classList.add("panel-hidden");
    });

    tabModePassphrase.addEventListener("click", () => {
        currentGenMode = "passphrase";
        tabModePassphrase.classList.add("active");
        tabModeRandom.classList.remove("active");
        controlsPassphrase.classList.remove("panel-hidden");
        controlsRandom.classList.add("panel-hidden");
    });

    lengthSlider.addEventListener("input", () => {
        sliderLengthVal.textContent = `${lengthSlider.value} characters`;
    });

    wordsSlider.addEventListener("input", () => {
        sliderWordsVal.textContent = `${wordsSlider.value} words`;
    });

    generateSubmitBtn.addEventListener("click", async () => {
        let payload = { mode: currentGenMode };

        if (currentGenMode === "passphrase") {
            payload.word_count = parseInt(wordsSlider.value, 10);
            payload.separator = passphraseSep.value;
            payload.capitalize = chkPassCapitalize.checked;
            payload.include_number = chkPassNumber.checked;
        } else {
            payload.length = parseInt(lengthSlider.value, 10);
            payload.use_upper = chkUpper.checked;
            payload.use_lower = chkLower.checked;
            payload.use_digits = chkDigits.checked;
            payload.use_special = chkSymbols.checked;
            payload.avoid_ambiguous = chkAmbiguous.checked;

            if (!payload.use_upper && !payload.use_lower && !payload.use_digits && !payload.use_special) {
                showToast("Select at least one character category.", "warning");
                return;
            }
        }

        try {
            const response = await fetch("/api/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                const err = await response.json();
                showToast(err.error || "Generation failed.", "danger");
                return;
            }

            const data = await response.json();
            const outputPassword = data.password || data.passphrase || "";
            generatedPasswordText.textContent = outputPassword;
            showToast("Secure password generated!", "info");

        } catch (error) {
            console.error("Generator request error:", error);
            showToast("Failed to generate password.", "danger");
        }
    });

    copyBtn.addEventListener("click", () => {
        const text = generatedPasswordText.textContent.trim();
        if (!text || text.includes("Click \"Generate Password\"")) {
            showToast("No generated password to copy.", "warning");
            return;
        }

        navigator.clipboard.writeText(text).then(() => {
            showToast("Password copied to clipboard!", "info");
        }).catch(() => {
            showToast("Failed to copy password to clipboard.", "danger");
        });
    });

    testGeneratedBtn.addEventListener("click", () => {
        const text = generatedPasswordText.textContent.trim();
        if (!text || text.includes("Click \"Generate Password\"")) {
            showToast("Generate a password first.", "warning");
            return;
        }

        passwordInput.value = text;
        charCounter.textContent = text.length;
        document.getElementById("analyzer-section").scrollIntoView({ behavior: "smooth" });
        performAnalysis(text);
        showToast("Generated password loaded into analyzer.", "info");
    });

    // -----------------------------------------------------------------------
    // Safe Telemetry / Audit Log Management
    // -----------------------------------------------------------------------
    async function refreshTelemetry() {
        try {
            const res = await fetch("/api/history");
            if (!res.ok) return;

            const data = await res.json();
            const history = data.history || [];
            const stats = data.statistics || {};

            // Update stats
            statsTotal.textContent = stats.total_evaluations || 0;
            statsAvg.textContent = stats.average_score || 0;

            const breakdown = stats.strength_breakdown || {};
            const strongCount = (breakdown["Strong"] || 0) + (breakdown["Very Strong"] || 0);
            const total = stats.total_evaluations || 0;
            const strongPct = total > 0 ? Math.round((strongCount / total) * 100) : 0;
            statsStrongPct.textContent = `${strongPct}%`;

            // Update table
            if (history.length === 0) {
                telemetryTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="text-center text-muted">No evaluations recorded yet in this session.</td>
                    </tr>
                `;
            } else {
                telemetryTableBody.innerHTML = history.map(item => `
                    <tr>
                        <td>${item.id}</td>
                        <td>${item.timestamp}</td>
                        <td><strong>${item.score}</strong> / 100</td>
                        <td><span class="badge-pill">${item.strength}</span></td>
                        <td>${item.length} chars</td>
                        <td>${item.entropy_bits} bits</td>
                    </tr>
                `).join("");
            }

        } catch (e) {
            console.error("Telemetry refresh error:", e);
        }
    }

    clearHistoryBtn.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/history/clear", { method: "POST" });
            if (res.ok) {
                showToast("Audit telemetry successfully purged.", "info");
                refreshTelemetry();
            }
        } catch (e) {
            showToast("Failed to clear telemetry.", "danger");
        }
    });

    // Initial load
    refreshTelemetry();
});
