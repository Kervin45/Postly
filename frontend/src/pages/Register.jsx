import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { API_BASE } from "@/config";

function Register() {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  });
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError("");

    const res = await fetch(`${API_BASE}/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(formData),
    });

    const data = await res.json();

    if (res.ok) {
      navigate("/");
    } else {
      setError(data.error || "Registration failed");
    }
  };

  return (
    <form onSubmit={handleRegister}>
      <input
        placeholder="Username"
        onChange={(e) =>
          setFormData({ ...formData, username: e.target.value })
        }
      />
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
      <button type="submit">Register</button>
    </form>
  );
}

export default Register;
