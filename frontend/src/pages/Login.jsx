import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE } from '../config'; // ✅ ADD THIS IMPORT

const styles = {
    container: { 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh', 
        backgroundColor: '#f3f4f6' 
    },
    card: { 
        backgroundColor: '#fff', 
        padding: '40px', 
        borderRadius: '16px', 
        boxShadow: '0 4px 6px rgba(0,0,0,0.1)', 
        width: '100%', 
        maxWidth: '400px' 
    },
    title: { 
        textAlign: 'center', 
        color: '#1e293b', 
        marginBottom: '20px' 
    },
    input: { 
        width: '100%',
        padding: '12px', 
        marginBottom: '15px',
        borderRadius: '8px', 
        border: '1px solid #e2e8f0', 
        outline: 'none',
        boxSizing: 'border-box'
    },
    button: { 
        width: '100%',
        padding: '12px', 
        borderRadius: '8px', 
        border: 'none', 
        backgroundColor: '#3b82f6', 
        color: '#fff',
        fontSize: '16px',
        fontWeight: '600',
        cursor: 'pointer'
    },
    link: { 
        textAlign: 'center', 
        fontSize: '14px', 
        color: '#6366f1', 
        cursor: 'pointer',
        marginTop: '15px'
    },
    error: {
        color: '#ef4444',
        fontSize: '14px',
        marginTop: '10px',
        textAlign: 'center'
    }
};

function Login() {
    const [formData, setFormData] = useState({ 
        email: '', 
        password: '' 
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError("");
        setLoading(true);

        try {
            // ✅ CHANGED: Use API_BASE instead of hardcoded URL
            const res = await fetch(`${API_BASE}/auth/login`, {
                method: "POST",
                headers: { 
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(formData),
            });

            const data = await res.json();

            if (res.ok) {
                localStorage.setItem("token", data.token || data.access_token);
                localStorage.setItem("userId", data.userId || data.user_id);
                localStorage.setItem("username", data.username);
                localStorage.setItem("email", data.email || formData.email);
                navigate("/feed");
            } else {
                setError(data.error || "Login failed");
            }
        } catch (err) {
            setError("Network error. Please check your connection.");
            console.error("Login error:", err);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={styles.container}>
            <form onSubmit={handleLogin} style={styles.card}>
                <h2 style={styles.title}>Welcome Back</h2>
                
                <input 
                    type="email" 
                    placeholder="Email" 
                    required 
                    style={styles.input}
                    value={formData.email}
                    onChange={e => setFormData({...formData, email: e.target.value})}
                    disabled={loading}
                />
                
                <input 
                    type="password" 
                    placeholder="Password" 
                    required 
                    style={styles.input}
                    value={formData.password}
                    onChange={e => setFormData({...formData, password: e.target.value})}
                    disabled={loading}
                />
                
                {error && <div style={styles.error}>{error}</div>}
                
                <button 
                    type="submit" 
                    style={styles.button}
                    disabled={loading}
                >
                    {loading ? 'Logging in...' : 'Login'}
                </button>
                
                <p 
                    onClick={() => navigate('/register')} 
                    style={styles.link}
                >
                    Don't have an account? Register here
                </p>
            </form>
        </div>
    );
}

export default Login;