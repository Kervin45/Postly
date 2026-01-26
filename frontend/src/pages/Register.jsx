import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { API_BASE } from "../config.js";

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

function Register() {
    const [formData, setFormData] = useState({ 
        username: '', 
        email: '', 
        password: '' 
    });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();

    const handleRegister = async (e) => {
        e.preventDefault();
        setError('');
        
        // Validation
        if (!formData.username.trim() || !formData.email.trim() || !formData.password.trim()) {
            setError('All fields are required');
            return;
        }
        
        if (formData.password.length < 3) {
            setError('Password must be at least 3 characters');
            return;
        }
        
        setLoading(true);
        
        try {
            console.log('Sending data:', formData);
            
            const res = await fetch('http://127.0.0.1:5000/auth/register', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            
            const data = await res.json();
            
            if (res.ok) {
                alert('Registration successful! Please login.');
                navigate('/');
            } else {
                setError(data.error || 'Registration failed. Please try again.');
            }
        } catch (err) {
            console.error('Registration error:', err);
            setError('Server error. Please check your connection.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={styles.container}>
            <form onSubmit={handleRegister} style={styles.card}>
                <h2 style={styles.title}>Join Postly</h2>
                
                <input 
                    type="text" 
                    placeholder="Username" 
                    required 
                    style={styles.input}
                    value={formData.username}
                    onChange={e => setFormData({...formData, username: e.target.value})}
                    disabled={loading}
                />
                
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
                    {loading ? 'Creating Account...' : 'Create Account'}
                </button>
                
                <p 
                    onClick={() => navigate('/')} 
                    style={styles.link}
                >
                    Already have an account? Login here
                </p>
            </form>
        </div>
    );
}

export default Register;