"use strict";

async function fetchJSON(
  url,
  options = {}
) {
  const response =
    await fetch(url, {
      ...options,
      headers: {
        "Content-Type":
          "application/json",
        ...(options.headers || {})
      }
    });

  let data = null;

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  return {
    ok: response.ok,
    status: response.status,
    data
  };
}

function escapeHTML(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatTime(timestamp) {
  return new Date(timestamp)
    .toLocaleTimeString();
}

function setScore(score) {
  const safeScore =
    Math.max(
      0,
      Math.min(
        100,
        Number(score) || 0
      )
    );

  document.getElementById(
    "score"
  ).textContent =
    safeScore;

  document.getElementById(
    "scoreText"
  ).textContent =
    `${safeScore} / 100`;

  document.getElementById(
    "scoreBar"
  ).style.width =
    `${safeScore}%`;
}

async function updateDashboard() {
  const result =
    await fetchJSON(
      "/api/dashboard"
    );

  if (!result.ok) {
    return;
  }

  const stats =
    result.data.stats;

  document.getElementById(
    "totalRequests"
  ).textContent =
    stats.totalRequests;

  document.getElementById(
    "blockedRequests"
  ).textContent =
    stats.blockedRequests;

  document.getElementById(
    "detectedThreats"
  ).textContent =
    stats.detectedThreats;

  document.getElementById(
    "activeBans"
  ).textContent =
    stats.activeBans;
}

async function updateProfile() {
  const result =
    await fetchJSON(
      "/api/test-status"
    );

  if (!result.ok) {
    return;
  }

  const profile =
    result.data;

  document.getElementById(
    "clientIP"
  ).textContent =
    profile.ip;

  document.getElementById(
    "banLevel"
  ).textContent =
    profile.banLevel;

  document.getElementById(
    "profileRequests"
  ).textContent =
    profile.requests;

  setScore(
    profile.score
  );

  renderHistory(
    profile.history
  );
}

function renderHistory(history) {
  const container =
    document.getElementById(
      "history"
    );

  if (
    !Array.isArray(history) ||
    history.length === 0
  ) {
    container.textContent =
      "No violations detected.";

    return;
  }

  container.innerHTML =
    history
      .slice(0, 20)
      .map(item => `
        <div class="history-item">

          <div>
            <strong>
              ${escapeHTML(
                item.violation
              )}
            </strong>

            <small>
              ${escapeHTML(
                formatTime(
                  item.timestamp
                )
              )}
            </small>
          </div>

          <span>
            +${escapeHTML(
              item.scoreAdded
            )}
          </span>

        </div>
      `)
      .join("");
}

async function updateEvents() {
  const result =
    await fetchJSON(
      "/api/events?limit=50"
    );

  if (!result.ok) {
    return;
  }

  const events =
    result.data.events;

  const tbody =
    document.getElementById(
      "events"
    );

  if (
    !Array.isArray(events) ||
    events.length === 0
  ) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6">
          No security events.
        </td>
      </tr>
    `;

    return;
  }

  tbody.innerHTML =
    events
      .map(event => `
        <tr>

          <td>
            ${escapeHTML(
              formatTime(
                event.timestamp
              )
            )}
          </td>

          <td>
            <span class="event ${escapeHTML(
              event.action
            )}">
              ${escapeHTML(
                event.action
              )}
            </span>
          </td>

          <td>
            ${escapeHTML(
              event.type
            )}
          </td>

          <td>
            ${escapeHTML(
              event.ip
            )}
          </td>

          <td>
            +${escapeHTML(
              event.scoreAdded
            )}
          </td>

          <td>
            ${escapeHTML(
              event.path
            )}
          </td>

        </tr>
      `)
      .join("");
}

async function refresh() {
  await Promise.all([
    updateDashboard(),
    updateProfile(),
    updateEvents()
  ]);
}

async function normalRequest() {
  const result =
    await fetchJSON(
      "/api/public"
    );

  console.log(
    "Normal request:",
    result
  );

  await refresh();
}

async function rateLimitTest() {
  console.log(
    "Starting defensive rate-limit test..."
  );

  const requests =
    Array.from(
      { length: 70 },
      () =>
        fetchJSON(
          "/api/public"
        )
    );

  await Promise.all(
    requests
  );

  await refresh();
}

async function sqliTest() {
  const result =
    await fetchJSON(
      "/api/search?q=test%20UNION%20SELECT%20users"
    );

  console.log(
    "SQLi detection test:",
    result
  );

  await refresh();
}

async function xssTest() {
  const result =
    await fetchJSON(
      "/api/login",
      {
        method: "POST",
        body: JSON.stringify({
          username:
            "<script>alert('test')</script>"
        })
      }
    );

  console.log(
    "XSS detection test:",
    result
  );

  await refresh();
}

async function scannerTest() {
  const result =
    await fetchJSON(
      "/api/public",
      {
        headers: {
          "User-Agent":
            "Nmap Scanner Test"
        }
      }
    );

  console.log(
    "Scanner detection test:",
    result
  );

  await refresh();
}

async function rceTest() {
  /*
   * This is a local defensive fixture.
   * Nothing is executed by the server.
   */
  const result =
    await fetchJSON(
      "/api/login",
      {
        method: "POST",
        body: JSON.stringify({
          test:
            "; whoami"
        })
      }
    );

  console.log(
    "Command detection test:",
    result
  );

  await refresh();
}

async function resetProfile() {
  const result =
    await fetchJSON(
      "/api/test-reset",
      {
        method: "POST"
      }
    );

  console.log(
    "Profile reset:",
    result
  );

  await refresh();
}

refresh();

setInterval(
  refresh,
  2000
);