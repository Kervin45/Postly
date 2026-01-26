import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { API_BASE } from "@/config";

function Login() {
  const [formData, setFormData] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const navigate = useNavigate();

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
      localStorage.setItem("token", data.access_token);
      localStorage.setItem("userId", data.user_id);
      localStorage.setItem("username", data.username);
      navigate("/feed");
    } else {
      setError(data.error || "Login failed");
    }
  };

  return (
    <form onSubmit={handleLogin}>
      <input
        placeholder="Email"
        onChange={(e) =>
          setFormData({ ...formData, email: e.target.value })
        }
      />
      <input
        type="password"
        placeholder="Password"
        onChange={(e) =>
          setFormData({ ...formData, password: e.target.value })
        }
      />
      {error && <p>{error}</p>}
      <button type="submit">Login</button>
    </form>
  );
}

export default Login;
