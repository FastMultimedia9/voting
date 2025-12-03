import React from 'react';
import './AboutPage.css';

const AboutPage = () => {
  return (
    <div className="about-page">
      <div className="about-hero">
        <h1>About Voting System</h1>
        <p className="hero-subtitle">Transparent, Secure, and Modern Voting Platform</p>
      </div>

      <div className="about-content">
        <div className="about-section">
          <h2>Our Mission</h2>
          <p>
            Our mission is to revolutionize the voting process by providing a secure, transparent, 
            and accessible platform for conducting elections. We believe in empowering communities 
            with technology that ensures every vote counts and is counted accurately.
          </p>
        </div>

        <div className="about-section">
          <h2>Key Features</h2>
          <div className="features-grid">
            <div className="feature-item">
              <div className="feature-icon">🔒</div>
              <h3>End-to-End Security</h3>
              <p>Military-grade encryption and blockchain technology ensure vote integrity.</p>
            </div>
            <div className="feature-item">
              <div className="feature-icon">👁️</div>
              <h3>Transparency</h3>
              <p>Real-time results and audit trails for complete transparency.</p>
            </div>
            <div className="feature-item">
              <div className="feature-icon">📱</div>
              <h3>Mobile First</h3>
              <p>Accessible on all devices with responsive design.</p>
            </div>
            <div className="feature-item">
              <div className="feature-icon">⚡</div>
              <h3>Real-time Updates</h3>
              <p>Live results and instant vote confirmation.</p>
            </div>
          </div>
        </div>

        <div className="about-section">
          <h2>Technology Stack</h2>
          <div className="tech-stack">
            <div className="tech-item">
              <span className="tech-name">React 18</span>
              <span className="tech-desc">Frontend Framework</span>
            </div>
            <div className="tech-item">
              <span className="tech-name">React Router v7</span>
              <span className="tech-desc">Routing</span>
            </div>
            <div className="tech-item">
              <span className="tech-name">Context API</span>
              <span className="tech-desc">State Management</span>
            </div>
            <div className="tech-item">
              <span className="tech-name">CSS3</span>
              <span className="tech-desc">Styling</span>
            </div>
          </div>
        </div>

        <div className="about-section">
          <h2>How It Works</h2>
          <div className="steps">
            <div className="step">
              <div className="step-number">1</div>
              <div className="step-content">
                <h3>Register & Verify</h3>
                <p>Users register with secure credentials and verify their identity.</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">2</div>
              <div className="step-content">
                <h3>Cast Your Vote</h3>
                <p>Browse candidates and submit your vote securely.</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">3</div>
              <div className="step-content">
                <h3>Instant Confirmation</h3>
                <p>Receive immediate confirmation of your vote submission.</p>
              </div>
            </div>
            <div className="step">
              <div className="step-number">4</div>
              <div className="step-content">
                <h3>View Results</h3>
                <p>Watch real-time results as votes are counted.</p>
              </div>
            </div>
          </div>
        </div>

        <div className="about-section contact-section">
          <h2>Contact Us</h2>
          <p>Have questions or need support? Reach out to our team.</p>
          <div className="contact-info">
            <p>📧 Email: support@votingsystem.com</p>
            <p>📞 Phone: (555) 123-4567</p>
            <p>🏢 Address: 123 Democracy Street, Election City</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AboutPage;