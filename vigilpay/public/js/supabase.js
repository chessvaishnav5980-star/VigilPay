let client = null;
let configuration = { configured: false, safeBrowsingConfigured: false };

export async function initBackend() {
  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    const config = await response.json();
    configuration.safeBrowsingConfigured = Boolean(config.safeBrowsingConfigured);
    if (config.supabaseUrl && config.supabaseKey && window.supabase?.createClient) {
      client = window.supabase.createClient(config.supabaseUrl, config.supabaseKey, {
        auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
      });
      configuration.configured = true;
    }
  } catch { /* Local mode is intentional when no server/config is available. */ }
  return configuration;
}

export function backendStatus() { return { ...configuration }; }

export async function getSession() {
  if (!client) return null;
  const { data } = await client.auth.getSession();
  return data.session || null;
}

export function onAuthChange(callback) {
  if (!client) return () => {};
  const { data } = client.auth.onAuthStateChange((_event, session) => callback(session));
  return () => data.subscription.unsubscribe();
}

export async function signIn(email, password) {
  if (!client) throw new Error("Supabase is not configured. Add the Render environment variables first.");
  const { data, error } = await client.auth.signInWithPassword({ email, password });
  if (error) throw error;
  return data;
}

export async function signUp(email, password) {
  if (!client) throw new Error("Supabase is not configured. Add the Render environment variables first.");
  const { data, error } = await client.auth.signUp({ email, password });
  if (error) throw error;
  return data;
}

export async function signOut() {
  if (!client) return;
  const { error } = await client.auth.signOut();
  if (error) throw error;
}

export async function getProfile() {
  const session = await getSession();
  if (!session) return null;
  const { data, error } = await client.from("profiles").select("display_name,role").eq("id", session.user.id).maybeSingle();
  if (error) return { role: "user", display_name: session.user.email?.split("@")[0] || "User" };
  return data || { role: "user", display_name: session.user.email?.split("@")[0] || "User" };
}

export async function searchApprovedReports(query = "") {
  if (!client) return null;
  const { data, error } = await client.rpc("search_community_reports", { search_query: query.trim() });
  if (error) throw error;
  return data;
}

function maskIdentifier(identifier, type) {
  const value = String(identifier).trim();
  if (type === "phone") return value.length > 4 ? `${value.slice(0, 3)} ••••• ${value.slice(-4)}` : "••••";
  if (type === "upi") {
    const [name, provider] = value.split("@");
    return `${(name || "").slice(0, 4)}•••${provider ? `@${provider}` : ""}`;
  }
  if (type === "account") return `•••• ${value.slice(-4)}`;
  if (type === "website") return value.replace(/^https?:\/\//, "").replace(/\.(?=[a-z]{2,}$)/i, "[.]");
  return value.length > 16 ? `${value.slice(0, 8)}•••${value.slice(-5)}` : value;
}

export async function submitCommunityReport(form) {
  if (!client) throw new Error("Community submissions need Supabase. The local demo can still be searched.");
  const session = await getSession();
  if (!session) throw new Error("Sign in before submitting a report.");
  const identifier = String(form.identifier).trim();
  const record = {
    user_id: session.user.id,
    identifier_type: form.identifier_type,
    identifier: identifier,
    identifier_display: maskIdentifier(identifier, form.identifier_type),
    report_type: form.report_type,
    incident_date: form.incident_date || null,
    description: String(form.description).trim(),
    status: "pending"
  };
  const { error } = await client.from("community_reports").insert(record);
  if (error) throw error;
}

export async function fetchModerationQueue() {
  if (!client) return [];
  const { data, error } = await client.from("community_reports").select("id,identifier_type,identifier_display,report_type,description,status,created_at").eq("status", "pending").order("created_at", { ascending: true }).limit(100);
  if (error) throw error;
  return data;
}

export async function moderateReport(id, status) {
  if (!client) throw new Error("Supabase is not configured.");
  const { error } = await client.from("community_reports").update({ status, reviewed_at: new Date().toISOString() }).eq("id", id);
  if (error) throw error;
}
