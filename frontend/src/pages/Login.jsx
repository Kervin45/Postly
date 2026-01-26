import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE } from "../config";

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
        setError('');
        
        if (!formData.email.trim() || !formData.password.trim()) {
            setError('Email and password are required');
            return;
        }
        
        setLoading(true);
        
        try {
            const res = await fetch('http://127.0.0.1:5000/auth/login', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            
            const data = await res.json();
            
            if (res.ok) {
                localStorage.setItem('token', data.token);
                localStorage.setItem('userId', data.userId);
                localStorage.setItem('username', data.username);
                navigate('/feed');
            } else {
                setError(data.error || 'Login failed. Please check your credentials.');
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('Server error. Please try again.');
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