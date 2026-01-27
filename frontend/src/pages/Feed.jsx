import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { API_BASE } from "@/config";

const styles = {
  container: { 
    maxWidth: "800px", 
    margin: "0 auto", 
    padding: "20px",
    minHeight: "100vh"
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "30px",
  },
  title: { 
    color: "#1e293b", 
    margin: 0,
    fontSize: "28px",
    fontWeight: "700"
  },
  logoutBtn: {
    padding: "8px 16px",
    backgroundColor: "#64748b",
    color: "white",
    border: "none",
    borderRadius: "6px",
    cursor: "pointer",
    fontWeight: "500",
    transition: "background-color 0.2s",
    "&:hover": {
      backgroundColor: "#475569"
    }
  },
  createPostSection: {
    backgroundColor: "white",
    padding: "25px",
    borderRadius: "12px",
    boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
    marginBottom: "30px",
    border: "1px solid #e2e8f0"
  },
  sectionTitle: {
    marginTop: "0",
    marginBottom: "15px",
    color: "#1e293b",
    fontSize: "20px"
  },
  textarea: {
    width: "100%",
    padding: "12px",
    border: "1px solid #e2e8f0",
    borderRadius: "8px",
    fontSize: "16px",
    marginBottom: "15px",
    minHeight: "100px",
    resize: "vertical",
    fontFamily: "inherit",
    transition: "border-color 0.2s",
    "&:focus": {
      outline: "none",
      borderColor: "#3b82f6",
      boxShadow: "0 0 0 3px rgba(59, 130, 246, 0.1)"
    }
  },
  postBtn: {
    padding: "12px 24px",
    backgroundColor: "#3b82f6",
    color: "white",
    border: "none",
    borderRadius: "8px",
    cursor: "pointer",
    fontSize: "16px",
    fontWeight: "600",
    transition: "background-color 0.2s",
    "&:hover": {
      backgroundColor: "#2563eb"
    },
    "&:disabled": {
      backgroundColor: "#93c5fd",
      cursor: "not-allowed"
    }
  },
  postsSection: {
    backgroundColor: "white",
    padding: "25px",
    borderRadius: "12px",
    boxShadow: "0 2px 8px rgba(0,0,0,0.08)",
    marginBottom: "40px",
    border: "1px solid #e2e8f0"
  },
  postCard: {
    borderBottom: "1px solid #e2e8f0",
    padding: "20px 0",
    "&:last-child": {
      borderBottom: "none"
    }
  },
  postContent: {
    fontSize: "16px",
    lineHeight: "1.6",
    color: "#374151",
    marginBottom: "12px"
  },
  postMeta: {
    fontSize: "14px",
    color: "#6b7280",
    marginBottom: "15px",
    display: "flex",
    alignItems: "center",
    gap: "8px"
  },
  postActions: { 
    display: "flex", 
    gap: "10px" 
  },
  editBtn: {
    padding: "6px 12px",
    backgroundColor: "#f59e0b",
    color: "white",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    fontSize: "14px",
    fontWeight: "500",
    transition: "background-color 0.2s",
    "&:hover": {
      backgroundColor: "#d97706"
    }
  },
  deleteBtn: {
    padding: "6px 12px",
    backgroundColor: "#ef4444",
    color: "white",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
    fontSize: "14px",
    fontWeight: "500",
    transition: "background-color 0.2s",
    "&:hover": {
      backgroundColor: "#dc2626"
    }
  },
  errorText: {
    color: "#ef4444",
    backgroundColor: "#fee2e2",
    padding: "10px",
    borderRadius: "6px",
    marginBottom: "15px",
    fontSize: "14px"
  },
  loadingText: {
    textAlign: "center",
    color: "#6b7280",
    padding: "20px",
    fontSize: "16px"
  },
  // Footer styles
  footer: {
    marginTop: "60px",
    paddingTop: "25px",
    borderTop: "1px solid #e2e8f0",
    textAlign: "center",
    fontSize: "14px",
    color: "#64748b"
  },
  footerText: {
    marginBottom: "12px",
    lineHeight: "1.5"
  },
  highlightName: {
    color: "#1e293b",
    fontWeight: "600"
  },
  socialLinks: {
    display: "flex",
    justifyContent: "center",
    gap: "20px",
    marginTop: "15px"
  },
  socialLink: {
    color: "#3b82f6",
    textDecoration: "none",
    fontWeight: "500",
    fontSize: "14px",
    padding: "6px 12px",
    borderRadius: "6px",
    transition: "all 0.2s",
    "&:hover": {
      color: "#2563eb",
      backgroundColor: "#eff6ff",
      textDecoration: "none"
    }
  },
  dotSeparator: {
    color: "#cbd5e1",
    userSelect: "none"
  }
};

function Feed() {
  const [newPost, setNewPost] = useState("");
  const [posts, setPosts] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const navigate = useNavigate();

  const token = localStorage.getItem("token");
  const userId = localStorage.getItem("userId");
  const username = localStorage.getItem("username");

  useEffect(() => {
    if (!token) {
      navigate("/");
      return;
    }
    fetchPosts();
  }, [token, navigate]);

  const fetchPosts = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/posts`);
      if (res.ok) {
        const data = await res.json();
        setPosts(data);
      }
    } catch (err) {
      console.error("Error fetching posts:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreatePost = async (e) => {
    e.preventDefault();
    setError("");

    if (!newPost.trim()) {
      setError("Post cannot be empty");
      return;
    }

    setIsCreating(true);
    try {
      const res = await fetch(`${API_BASE}/posts`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ content: newPost }),
      });

      if (res.ok) {
        setNewPost("");
        fetchPosts();
      } else {
        const data = await res.json();
        setError(data.error || "Failed to create post");
      }
    } catch (err) {
      setError("Network error. Please try again.");
    } finally {
      setIsCreating(false);
    }
  };

  const handleEditPost = async (id, currentContent) => {
    const updated = prompt("Edit your post:", currentContent);
    if (updated === null || updated.trim() === "" || updated === currentContent) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/posts/${id}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ content: updated.trim() }),
      });

      if (res.ok) {
        fetchPosts();
      } else {
        const data = await res.json();
        alert(data.error || "Failed to edit post");
      }
    } catch (err) {
      alert("Error updating post");
    }
  };

  const handleDeletePost = async (id) => {
    if (!window.confirm("Are you sure you want to delete this post?")) {
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/posts/${id}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (res.ok) {
        fetchPosts();
      } else {
        const data = await res.json();
        alert(data.error || "Failed to delete post");
      }
    } catch (err) {
      alert("Error deleting post");
    }
  };

  const handleLogout = () => {
    localStorage.clear();
    navigate("/");
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <h1 style={styles.title}>Postly Feed</h1>
        <div>
          <span style={{ marginRight: "15px", color: "#4b5563" }}>
            Welcome, <strong>{username || "User"}</strong>
          </span>
          <button 
            style={styles.logoutBtn} 
            onClick={handleLogout}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Create Post Section */}
      <div style={styles.createPostSection}>
        <h2 style={styles.sectionTitle}>Create Post</h2>
        <form onSubmit={handleCreatePost}>
          <textarea
            style={styles.textarea}
            value={newPost}
            onChange={(e) => setNewPost(e.target.value)}
            placeholder="What's on your mind?"
            disabled={isCreating}
          />
          {error && <div style={styles.errorText}>{error}</div>}
          <button 
            style={styles.postBtn} 
            type="submit"
            disabled={isCreating || !newPost.trim()}
          >
            {isCreating ? "Posting..." : "Post to Feed"}
          </button>
        </form>
      </div>

      {/* Posts Section */}
      <div style={styles.postsSection}>
        <h2 style={styles.sectionTitle}>Recent Posts</h2>
        
        {loading ? (
          <div style={styles.loadingText}>Loading posts...</div>
        ) : posts.length === 0 ? (
          <div style={styles.loadingText}>No posts yet. Be the first to share something!</div>
        ) : (
          posts.map((post) => (
            <div key={post.id} style={styles.postCard}>
              <div style={styles.postContent}>{post.content}</div>
              <div style={styles.postMeta}>
                <span>Posted by <strong>{post.username}</strong></span>
                {post.created_at && (
                  <>
                    <span>•</span>
                    <span>{post.created_at}</span>
                  </>
                )}
              </div>
              
              {post.user_id === Number(userId) && (
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

      {/* Personal Links Footer */}
      <div style={styles.footer}>
        <p style={styles.footerText}>
          👋 Built by <span style={styles.highlightName}>Kervin Kittuselvan</span> — an IT engineering student
        </p>
        <div style={styles.socialLinks}>
          <a 
            href="https://www.linkedin.com/in/kervin-kittuselvan-6b2927256" 
            target="_blank" 
            rel="noopener noreferrer"
            style={styles.socialLink}
          >
            LinkedIn
          </a>
          <span style={styles.dotSeparator}>•</span>
          <a 
            href="https://github.com/Kervin45" 
            target="_blank" 
            rel="noopener noreferrer"
            style={styles.socialLink}
          >
            GitHub
          </a>
          <span style={styles.dotSeparator}>•</span>
          <a 
            href="https://www.instagram.com/its.me_kervin?igsh=MTU2Mm0xN283ZHM1Yw==" 
            target="_blank" 
            rel="noopener noreferrer"
            style={styles.socialLink}
          >
            Instagram
          </a>
        </div>
      </div>
    </div>
  );
}

export default Feed;
