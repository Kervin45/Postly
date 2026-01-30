const handleLogin = async (e) => {
  e.preventDefault();
  setError("");

  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(formData),
  });

  const data = await res.json();

  if (res.ok) {
    localStorage.setItem("token", data.token);      // 🔥 FIX
    localStorage.setItem("userId", data.userId);
    localStorage.setItem("username", data.username);
    navigate("/feed");
  } else {
    setError(data.error || "Login failed");
  }
};
