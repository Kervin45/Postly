import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const styles = {
    container: { 
        maxWidth: '800px', 
        margin: '0 auto', 
        padding: '20px' 
    },
    header: { 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        marginBottom: '30px' 
    },
    title: { 
        color: '#1e293b', 
        margin: 0 
    },
    logoutBtn: { 
        padding: '8px 16px', 
        backgroundColor: '#64748b', 
        color: 'white', 
        border: 'none', 
        borderRadius: '6px', 
        cursor: 'pointer' 
    },
    createPostSection: { 
        backgroundColor: 'white', 
        padding: '20px', 
        borderRadius: '12px', 
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)', 
        marginBottom: '30px' 
    },
    textarea: { 
        width: '100%', 
        padding: '12px', 
        border: '1px solid #e2e8f0', 
        borderRadius: '8px', 
        fontSize: '16px', 
        marginBottom: '15px', 
        minHeight: '100px',
        resize: 'vertical'
    },
    postBtn: { 
        padding: '12px 24px', 
        backgroundColor: '#3b82f6', 
        color: 'white', 
        border: 'none', 
        borderRadius: '8px', 
        cursor: 'pointer',
        fontSize: '16px',
        fontWeight: '600'
    },
    postsSection: { 
        backgroundColor: 'white', 
        padding: '20px', 
        borderRadius: '12px', 
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)' 
    },
    postCard: { 
        borderBottom: '1px solid #e2e8f0', 
        padding: '20px 0',
        '&:last-child': { borderBottom: 'none' }
    },
    postContent: { 
        fontSize: '16px', 
        marginBottom: '10px',
        color: '#374151'
    },
    postMeta: { 
        fontSize: '14px', 
        color: '#6b7280',
        marginBottom: '10px'
    },
    postActions: { 
        display: 'flex', 
        gap: '10px' 
    },
    editBtn: { 
        padding: '6px 12px', 
        backgroundColor: '#fbbf24', 
        color: 'white', 
        border: 'none', 
        borderRadius: '4px', 
        cursor: 'pointer' 
    },
    deleteBtn: { 
        padding: '6px 12px', 
        backgroundColor: '#ef4444', 
        color: 'white', 
        border: 'none', 
        borderRadius: '4px', 
        cursor: 'pointer' 
    },
    loading: {
        textAlign: 'center',
        color: '#6b7280',
        padding: '20px'
    },
    error: {
        color: '#ef4444',
        backgroundColor: '#fee2e2',
        padding: '10px',
        borderRadius: '6px',
        marginBottom: '15px'
    }
};

function Feed() {
    const [newPost, setNewPost] = useState('');
    const [posts, setPosts] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const token = localStorage.getItem('token');
    const userId = localStorage.getItem('userId');

    useEffect(() => {
        if (!token) {
            navigate('/');
            return;
        }
        fetchPosts();
    }, [token, navigate]);

    const fetchPosts = async () => {
        try {
            const response = await fetch('http://127.0.0.1:5000/posts', {
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                setPosts(data);
            } else {
                console.error('Failed to fetch posts');
            }
        } catch (err) {
            console.error('Error fetching posts:', err);
        }
    };

    const handleCreatePost = async (e) => {
    e.preventDefault();
    setError('');
    
    if (!newPost.trim()) {
        setError('Post content cannot be empty');
        return;
    }
    
    setLoading(true);
    
    try {
        console.log("Creating post with content:", newPost);
        console.log("Token:", token);
        
        const response = await fetch('http://127.0.0.1:5000/posts', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ 
                content: newPost 
            })
        });
        
        console.log("Response status:", response.status);
        console.log("Response headers:", response.headers);
        
        const data = await response.json();
        console.log("Response data:", data);
        
        if (response.ok) {
            setNewPost('');
            fetchPosts();
            alert('Post created successfully!');
        } else {
            setError(data.error || `Failed to create post (Status: ${response.status})`);
        }
    } catch (err) {
        console.error('Error creating post:', err);
        setError('Server error. Please try again.');
    } finally {
        setLoading(false);
    }
};

    const handleEditPost = async (postId, currentContent) => {
        const newContent = prompt('Edit your post:', currentContent);
        
        if (newContent === null || newContent.trim() === '' || newContent === currentContent) {
            return;
        }
        
        try {
            const response = await fetch(`http://127.0.0.1:5000/posts/${postId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ content: newContent })
            });
            
            if (response.ok) {
                fetchPosts();
            } else {
                const data = await response.json();
                alert(data.error || 'Failed to edit post');
            }
        } catch (err) {
            console.error('Error editing post:', err);
            alert('Server error. Please try again.');
        }
    };

    const handleDeletePost = async (postId) => {
        if (!window.confirm('Are you sure you want to delete this post?')) {
            return;
        }
        
        try {
            const response = await fetch(`http://127.0.0.1:5000/posts/${postId}`, {
                method: 'DELETE',
                headers: {
                    'Accept': 'application/json',
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                fetchPosts();
            } else {
                const data = await response.json();
                alert(data.error || 'Failed to delete post');
            }
        } catch (err) {
            console.error('Error deleting post:', err);
            alert('Server error. Please try again.');
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('userId');
        localStorage.removeItem('username');
        navigate('/');
    };

    if (!token) {
        return null; // Will redirect in useEffect
    }

    return (
        <div style={styles.container}>
            <div style={styles.header}>
                <h1 style={styles.title}>Postly Feed</h1>
                <button style={styles.logoutBtn} onClick={handleLogout}>
                    Logout
                </button>
            </div>
            
            <div style={styles.createPostSection}>
                <h2>Create Post</h2>
                {error && <div style={styles.error}>{error}</div>}
                <form onSubmit={handleCreatePost}>
                    <textarea
                        style={styles.textarea}
                        placeholder="What's on your mind?"
                        value={newPost}
                        onChange={(e) => setNewPost(e.target.value)}
                        disabled={loading}
                    />
                    <button 
                        style={styles.postBtn} 
                        type="submit" 
                        disabled={loading || !newPost.trim()}
                    >
                        {loading ? 'Posting...' : 'Post to Feed'}
                    </button>
                </form>
            </div>
            
            <div style={styles.postsSection}>
                <h2>Recent Posts</h2>
                {posts.length === 0 ? (
                    <div style={styles.loading}>No posts yet. Be the first to post!</div>
                ) : (
                    posts.map((post) => (
                        <div key={post.id} style={styles.postCard}>
                            <div style={styles.postContent}>{post.content}</div>
                            <div style={styles.postMeta}>
                                Posted by <strong>{post.username}</strong> on {post.created_at}
                            </div>
                            {parseInt(userId) === post.user_id && (
                                <div style={styles.postActions}>
                                    <button 
                                        style={styles.editBtn}
                                        onClick={() => handleEditPost(post.id, post.content)}
                                    >
                                        Edit
                                    </button>
                                    <button 
                                        style={styles.deleteBtn}
                                        onClick={() => handleDeletePost(post.id)}
                                    >
                                        Delete
                                    </button>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}

export default Feed;