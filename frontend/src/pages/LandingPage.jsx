import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  Database,
  Lock,
  Menu,
  RotateCcw,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react'
import './LandingPage.css'

export default function LandingPage() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const scrollToSection = (sectionId) => {
    const element = document.getElementById(sectionId)
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' })
      setMobileMenuOpen(false)
    }
  }

  return (
    <div className="landing-page">
      <nav className="landing-nav" aria-label="Main navigation">
        <div className="landing-nav-container">
          <Link to="/" className="landing-brand" aria-label="ARBR Home">
            <div className="landing-brand-mark">
              <Shield size={24} strokeWidth={2.2} />
            </div>
            <div className="landing-brand-text">
              <span className="landing-brand-name">ARBR</span>
              <span className="landing-brand-subtitle">Attack-Resistant Backup & Recovery</span>
            </div>
          </Link>

          <button
            className="landing-menu-toggle"
            aria-label="Toggle menu"
            aria-expanded={mobileMenuOpen}
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>

          <div className={`landing-nav-links ${mobileMenuOpen ? 'landing-nav-links--open' : ''}`}>
            <button onClick={() => scrollToSection('hero')} className="landing-nav-link">Home</button>
            <button onClick={() => scrollToSection('platform')} className="landing-nav-link">Platform</button>
            <button onClick={() => scrollToSection('how-it-works')} className="landing-nav-link">How It Works</button>
            <button onClick={() => scrollToSection('security')} className="landing-nav-link">Security</button>
            <Link to="/login" className="landing-nav-link landing-nav-link--auth">Sign In</Link>
            <Link to="/register" className="landing-nav-cta">Get Started</Link>
          </div>
        </div>
      </nav>

      <section id="hero" className="landing-hero">
        <div className="landing-hero-bg" aria-hidden="true">
          <div className="landing-tech-grid" />
          <svg className="landing-hero-network" viewBox="0 0 1400 800" fill="none">
            <defs>
              <linearGradient id="networkGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="rgba(8, 199, 216, 0.1)" />
                <stop offset="50%" stopColor="rgba(8, 199, 216, 0.05)" />
                <stop offset="100%" stopColor="rgba(8, 199, 216, 0.1)" />
              </linearGradient>
            </defs>
            <rect x="100" y="100" width="200" height="150" rx="8" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="url(#networkGrad)" />
            <rect x="400" y="200" width="180" height="120" rx="8" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="url(#networkGrad)" />
            <rect x="700" y="150" width="220" height="140" rx="8" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="url(#networkGrad)" />
            <rect x="1000" y="250" width="200" height="130" rx="8" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="url(#networkGrad)" />
            <line x1="300" y1="175" x2="400" y2="260" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" />
            <line x1="580" y1="260" x2="700" y2="220" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" />
            <line x1="920" y1="220" x2="1000" y2="315" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" />
            <circle cx="350" cy="220" r="6" fill="rgba(8, 199, 216, 0.15)" />
            <circle cx="640" cy="240" r="6" fill="rgba(8, 199, 216, 0.15)" />
            <circle cx="960" cy="270" r="6" fill="rgba(8, 199, 216, 0.15)" />
            <rect x="200" y="400" width="250" height="180" rx="8" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <rect x="550" y="450" width="200" height="140" rx="8" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <rect x="850" y="420" width="230" height="160" rx="8" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <line x1="325" y1="490" x2="550" y2="520" stroke="rgba(8, 199, 216, 0.04)" strokeWidth="1" />
            <line x1="750" y1="520" x2="850" y2="500" stroke="rgba(8, 199, 216, 0.04)" strokeWidth="1" />
            <circle cx="440" cy="505" r="5" fill="rgba(8, 199, 216, 0.12)" />
            <circle cx="800" cy="510" r="5" fill="rgba(8, 199, 216, 0.12)" />
          </svg>
          <svg className="landing-tech-circuit" viewBox="0 0 200 200" fill="none">
            <circle cx="100" cy="100" r="80" stroke="rgba(8, 199, 216, 0.2)" strokeWidth="1" />
            <circle cx="100" cy="100" r="60" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <circle cx="100" cy="100" r="40" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
            <line x1="100" y1="20" x2="100" y2="180" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
            <line x1="20" y1="100" x2="180" y2="100" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
            <line x1="44" y1="44" x2="156" y2="156" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
            <line x1="156" y1="44" x2="44" y2="156" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
          </svg>
          <svg className="landing-tech-circuit-2" viewBox="0 0 180 180" fill="none">
            <rect x="30" y="30" width="120" height="120" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <rect x="50" y="50" width="80" height="80" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" />
            <rect x="70" y="70" width="40" height="40" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" />
          </svg>
          <svg className="landing-tech-nodes" viewBox="0 0 300 200" fill="none">
            <circle cx="50" cy="50" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="150" cy="30" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="250" cy="50" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="100" cy="100" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="200" cy="100" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="50" cy="150" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="150" cy="170" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <circle cx="250" cy="150" r="4" fill="rgba(8, 199, 216, 0.3)" />
            <line x1="50" y1="50" x2="150" y2="30" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="150" y1="30" x2="250" y2="50" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="50" y1="50" x2="100" y2="100" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="150" y1="30" x2="100" y2="100" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="150" y1="30" x2="200" y2="100" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="250" y1="50" x2="200" y2="100" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="100" y1="100" x2="50" y2="150" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="100" y1="100" x2="150" y2="170" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="200" y1="100" x2="150" y2="170" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="200" y1="100" x2="250" y2="150" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="50" y1="150" x2="150" y2="170" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
            <line x1="150" y1="170" x2="250" y2="150" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" />
          </svg>
          <div className="landing-tech-square landing-tech-square--1" />
          <div className="landing-tech-square landing-tech-square--2" />
          <div className="landing-tech-square landing-tech-square--3" />
          <div className="landing-tech-square landing-tech-square--4" />
          <div className="landing-tech-node landing-tech-node--1" />
          <div className="landing-tech-node landing-tech-node--2" />
          <div className="landing-tech-node landing-tech-node--3" />
          <div className="landing-tech-node landing-tech-node--4" />
          <div className="landing-tech-node landing-tech-node--5" />
          <div className="landing-tech-node landing-tech-node--6" />
          <div className="landing-tech-line landing-tech-line--1" />
          <div className="landing-tech-line landing-tech-line--2" />
          <div className="landing-tech-line landing-tech-line--3" />
          <div className="landing-tech-line landing-tech-line--4" />
        </div>
        <div className="landing-hero-content">
          <div className="landing-hero-text">
            <span className="landing-eyebrow">
              <Activity size={16} strokeWidth={2} />
              DEFENSIVE OPERATIONS PLATFORM
            </span>
            <h1>Resilient Backups. Trusted Recovery. Stronger Security.</h1>
            <p>
              ARBR helps security teams monitor critical assets, detect suspicious activity, protect backups,
              prioritize risks, and verify recovery workflows against ransomware and other destructive threats.
            </p>
            <div className="landing-hero-ctas">
              <Link to="/register" className="landing-cta landing-cta--primary">
                Get Started <ArrowRight size={18} />
              </Link>
              <Link to="/login" className="landing-cta landing-cta--secondary">
                Sign In
              </Link>
            </div>
          </div>
          <div className="landing-hero-visual" aria-hidden="true">
            <div className="landing-hero-grid" />
            <svg className="landing-hero-shield-bg" viewBox="0 0 300 300" fill="none">
              <polygon points="150,20 270,80 270,220 150,280 30,220 30,80" stroke="rgba(8, 199, 216, 0.15)" strokeWidth="1" fill="none" />
              <polygon points="150,40 250,90 250,210 150,260 50,210 50,90" stroke="rgba(8, 199, 216, 0.1)" strokeWidth="1" fill="none" />
              <polygon points="150,60 230,100 230,200 150,240 70,200 70,100" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="none" />
            </svg>
            <div className="landing-hero-icon">
              <ShieldCheck size={120} strokeWidth={1.5} />
            </div>
            <div className="landing-hero-badge">
              <Shield size={20} strokeWidth={2} />
              <span>Protected</span>
            </div>
          </div>
        </div>
      </section>

      <section id="platform" className="landing-section landing-section--alt">
        <div className="landing-section-bg" aria-hidden="true">
          <div className="landing-section-grid" />
          <svg className="landing-platform-bg" viewBox="0 0 1200 600" fill="none">
            <rect x="0" y="0" width="1200" height="600" fill="none" />
            <circle cx="200" cy="150" r="80" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" />
            <circle cx="200" cy="150" r="120" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <circle cx="1000" cy="450" r="100" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" />
            <circle cx="1000" cy="450" r="150" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="200" y1="150" x2="400" y2="300" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="400" y1="300" x2="600" y2="300" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="600" y1="300" x2="800" y2="300" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="800" y1="300" x2="1000" y2="450" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <rect x="350" y="100" width="100" height="100" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" fill="none" />
            <rect x="750" y="400" width="100" height="100" stroke="rgba(8, 199, 216, 0.06)" strokeWidth="1" fill="none" />
          </svg>
        </div>
        <div className="landing-container">
          <div className="landing-section-header">
            <span className="landing-section-eyebrow">PLATFORM</span>
            <h2>Comprehensive Backup & Recovery Operations</h2>
            <p>Everything security teams need to protect, monitor, and recover critical infrastructure.</p>
          </div>

          <div className="landing-platform-grid">
            <div className="landing-platform-panel landing-platform-panel--large">
              <div className="landing-platform-visual">
                <svg className="landing-platform-illustration" viewBox="0 0 300 200" fill="none">
                  <rect x="50" y="30" width="200" height="140" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <rect x="70" y="50" width="60" height="40" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.08)" />
                  <rect x="150" y="50" width="80" height="40" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.08)" />
                  <rect x="70" y="110" width="160" height="40" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.08)" />
                  <circle cx="180" cy="70" r="4" fill="rgba(8, 199, 216, 0.6)" />
                  <circle cx="190" cy="70" r="4" fill="rgba(8, 199, 216, 0.4)" />
                  <circle cx="200" cy="70" r="4" fill="rgba(8, 199, 216, 0.2)" />
                  <line x1="100" y1="70" x2="140" y2="70" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <line x1="100" y1="130" x2="200" y2="130" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                </svg>
              </div>
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--shield">
                  <Shield size={36} strokeWidth={2} />
                </div>
                <h3>Threat Detection</h3>
                <p>Monitor security events and detect suspicious activity across your backup infrastructure with real-time alerting.</p>
              </div>
            </div>

            <div className="landing-platform-panel landing-platform-panel--wide">
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--database">
                  <Database size={36} strokeWidth={2} />
                </div>
                <h3>Backup Management</h3>
                <p>Track backup integrity, schedule automated verification, and ensure recovery points are available when needed.</p>
              </div>
              <div className="landing-platform-visual landing-platform-visual--right">
                <svg className="landing-platform-illustration" viewBox="0 0 300 200" fill="none">
                  <ellipse cx="150" cy="60" rx="80" ry="20" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <path d="M70 60 L70 140 A80 20 0 0 0 230 140 L230 60" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <ellipse cx="150" cy="140" rx="80" ry="20" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.08)" />
                  <rect x="100" y="85" width="100" height="30" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <line x1="110" y1="100" x2="190" y2="100" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" />
                </svg>
              </div>
            </div>

            <div className="landing-platform-panel landing-platform-panel--wide">
              <div className="landing-platform-visual">
                <svg className="landing-platform-illustration" viewBox="0 0 300 200" fill="none">
                  <circle cx="150" cy="100" r="60" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <path d="M150 40 L150 60 M150 140 L150 160 M90 100 L110 100 M190 100 L210 100" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" />
                  <path d="M110 60 L125 75 M190 60 L175 75 M110 140 L125 125 M190 140 L175 125" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" />
                  <circle cx="150" cy="100" r="25" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.1)" />
                  <path d="M150 85 L150 115 M135 100 L165 100" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1.5" />
                </svg>
              </div>
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--rotate">
                  <RotateCcw size={36} strokeWidth={2} />
                </div>
                <h3>Recovery Workflows</h3>
                <p>Validate and execute recovery procedures to quickly restore systems after ransomware or destructive attacks.</p>
              </div>
            </div>

            <div className="landing-platform-panel landing-platform-panel--medium">
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--lock">
                  <Lock size={36} strokeWidth={2} />
                </div>
                <h3>System Isolation</h3>
                <p>Isolate compromised systems to prevent lateral movement and protect clean recovery environments.</p>
              </div>
              <div className="landing-platform-visual landing-platform-visual--compact">
                <svg className="landing-platform-illustration" viewBox="0 0 200 150" fill="none">
                  <rect x="30" y="30" width="60" height="90" rx="4" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <rect x="110" y="30" width="60" height="90" rx="4" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <line x1="90" y1="60" x2="110" y2="60" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="2" strokeDasharray="4 2" />
                  <circle cx="100" cy="60" r="8" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="50" y="50" width="20" height="15" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="130" y="50" width="20" height="15" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                </svg>
              </div>
            </div>

            <div className="landing-platform-panel landing-platform-panel--medium">
              <div className="landing-platform-visual landing-platform-visual--compact">
                <svg className="landing-platform-illustration" viewBox="0 0 200 150" fill="none">
                  <rect x="20" y="40" width="160" height="70" rx="4" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <line x1="40" y1="75" x2="160" y2="75" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <circle cx="60" cy="55" r="6" fill="rgba(8, 199, 216, 0.4)" />
                  <circle cx="80" cy="55" r="6" fill="rgba(8, 199, 216, 0.3)" />
                  <circle cx="100" cy="55" r="6" fill="rgba(8, 199, 216, 0.2)" />
                  <rect x="40" y="95" width="40" height="8" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="90" y="95" width="50" height="8" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                </svg>
              </div>
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--activity">
                  <Activity size={36} strokeWidth={2} />
                </div>
                <h3>Risk Analysis</h3>
                <p>Prioritize vulnerabilities and assess risk exposure across backup and recovery infrastructure.</p>
              </div>
            </div>

            <div className="landing-platform-panel landing-platform-panel--medium">
              <div className="landing-platform-content">
                <div className="landing-platform-icon landing-platform-icon--shield-check">
                  <ShieldCheck size={36} strokeWidth={2} />
                </div>
                <h3>Audit Logging</h3>
                <p>Maintain comprehensive audit trails for compliance and post-incident forensic analysis.</p>
              </div>
              <div className="landing-platform-visual landing-platform-visual--compact">
                <svg className="landing-platform-illustration" viewBox="0 0 200 150" fill="none">
                  <rect x="30" y="20" width="140" height="110" rx="4" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <line x1="50" y1="45" x2="150" y2="45" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <line x1="50" y1="65" x2="150" y2="65" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <line x1="50" y1="85" x2="150" y2="85" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <line x1="50" y1="105" x2="120" y2="105" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <circle cx="140" cy="105" r="6" fill="rgba(8, 199, 216, 0.4)" />
                  <circle cx="140" cy="45" r="4" fill="rgba(8, 199, 216, 0.3)" />
                  <circle cx="140" cy="65" r="4" fill="rgba(8, 199, 216, 0.3)" />
                  <circle cx="140" cy="85" r="4" fill="rgba(8, 199, 216, 0.3)" />
                </svg>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="landing-section">
        <div className="landing-section-bg" aria-hidden="true">
          <div className="landing-section-grid" />
          <svg className="landing-workflow-bg" viewBox="0 0 1200 600" fill="none">
            <line x1="100" y1="100" x2="300" y2="200" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="300" y1="200" x2="500" y2="150" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="500" y1="150" x2="700" y2="250" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="700" y1="250" x2="900" y2="200" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <line x1="900" y1="200" x2="1100" y2="300" stroke="rgba(8, 199, 216, 0.05)" strokeWidth="1" />
            <circle cx="100" cy="100" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <circle cx="300" cy="200" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <circle cx="500" cy="150" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <circle cx="700" cy="250" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <circle cx="900" cy="200" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
            <circle cx="1100" cy="300" r="30" stroke="rgba(8, 199, 216, 0.08)" strokeWidth="1" fill="rgba(8, 199, 216, 0.03)" />
          </svg>
        </div>
        <div className="landing-container">
          <div className="landing-section-header">
            <span className="landing-section-eyebrow">WORKFLOW</span>
            <h2>How ARBR Works</h2>
            <p>A streamlined approach to backup security and recovery readiness.</p>
          </div>

          <div className="landing-workflow-grid">
            <div className="landing-workflow-step">
              <div className="landing-workflow-number">01</div>
              <div className="landing-workflow-visual">
                <svg className="landing-workflow-illustration" viewBox="0 0 280 180" fill="none">
                  <rect x="20" y="30" width="100" height="120" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <rect x="160" y="30" width="100" height="120" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <line x1="120" y1="90" x2="160" y2="90" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="2" />
                  <circle cx="140" cy="90" r="8" fill="rgba(8, 199, 216, 0.3)" />
                  <rect x="35" y="50" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="35" y="80" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="35" y="110" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="175" y="50" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="175" y="80" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="175" y="110" width="70" height="20" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <circle cx="70" cy="60" r="4" fill="rgba(8, 199, 216, 0.4)" />
                  <circle cx="210" cy="60" r="4" fill="rgba(8, 199, 216, 0.4)" />
                </svg>
              </div>
              <div className="landing-workflow-content">
                <h3>Monitor Assets</h3>
                <p>Connect your backup systems and begin monitoring security events and backup integrity in real-time.</p>
              </div>
            </div>

            <div className="landing-workflow-step">
              <div className="landing-workflow-number">02</div>
              <div className="landing-workflow-visual">
                <svg className="landing-workflow-illustration" viewBox="0 0 280 180" fill="none">
                  <rect x="40" y="40" width="200" height="100" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <line x1="40" y1="70" x2="240" y2="70" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1" />
                  <circle cx="60" cy="55" r="5" fill="rgba(8, 199, 216, 0.4)" />
                  <circle cx="80" cy="55" r="5" fill="rgba(8, 199, 216, 0.3)" />
                  <circle cx="100" cy="55" r="5" fill="rgba(8, 199, 216, 0.2)" />
                  <rect x="60" y="85" width="40" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="110" y="85" width="60" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="180" y="85" width="40" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="60" y="110" width="30" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="100" y="110" width="70" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="180" y="110" width="30" height="10" rx="2" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <circle cx="220" cy="55" r="6" fill="rgba(239, 62, 76, 0.4)" />
                </svg>
              </div>
              <div className="landing-workflow-content">
                <h3>Detect Threats</h3>
                <p>Automated threat detection identifies suspicious activity and potential ransomware indicators.</p>
              </div>
            </div>

            <div className="landing-workflow-step">
              <div className="landing-workflow-number">03</div>
              <div className="landing-workflow-visual">
                <svg className="landing-workflow-illustration" viewBox="0 0 280 180" fill="none">
                  <ellipse cx="140" cy="50" rx="70" ry="20" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <path d="M70 50 L70 130 A70 20 0 0 0 210 130 L210 50" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <ellipse cx="140" cy="130" rx="70" ry="20" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.08)" />
                  <rect x="90" y="75" width="100" height="30" rx="4" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <line x1="100" y1="90" x2="180" y2="90" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" />
                  <circle cx="140" cy="90" r="8" fill="rgba(8, 199, 216, 0.3)" />
                  <circle cx="200" cy="40" r="8" fill="rgba(35, 200, 121, 0.4)" />
                </svg>
              </div>
              <div className="landing-workflow-content">
                <h3>Protect Backups</h3>
                <p>Validate backup integrity and ensure recovery points are isolated and immutable when needed.</p>
              </div>
            </div>

            <div className="landing-workflow-step">
              <div className="landing-workflow-number">04</div>
              <div className="landing-workflow-visual">
                <svg className="landing-workflow-illustration" viewBox="0 0 280 180" fill="none">
                  <rect x="30" y="30" width="80" height="120" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <rect x="170" y="30" width="80" height="120" rx="8" stroke="rgba(8, 199, 216, 0.3)" strokeWidth="1.5" fill="rgba(8, 199, 216, 0.05)" />
                  <path d="M110 90 L140 60 L170 90" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="2" fill="none" />
                  <path d="M110 90 L140 120 L170 90" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="2" fill="none" />
                  <circle cx="140" cy="90" r="10" fill="rgba(8, 199, 216, 0.3)" />
                  <line x1="140" y1="80" x2="140" y2="100" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1.5" />
                  <line x1="130" y1="90" x2="150" y2="90" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1.5" />
                  <rect x="45" y="50" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="45" y="75" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="45" y="100" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="45" y="125" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="185" y="50" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="185" y="75" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="185" y="100" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                  <rect x="185" y="125" width="50" height="15" rx="3" stroke="rgba(8, 199, 216, 0.4)" strokeWidth="1" fill="rgba(8, 199, 216, 0.1)" />
                </svg>
              </div>
              <div className="landing-workflow-content">
                <h3>Recover Systems</h3>
                <p>Execute verified recovery workflows to restore systems from clean, validated backup snapshots.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="security" className="landing-section landing-section--alt">
        <div className="landing-section-bg" aria-hidden="true">
          <div className="landing-section-grid" />
        </div>
        <div className="landing-container">
          <div className="landing-section-header">
            <span className="landing-section-eyebrow">SECURITY</span>
            <h2>Built on Security Best Practices</h2>
            <p>ARBR implements industry-standard security controls to protect your operations.</p>
          </div>

          <div className="landing-security-grid">
            <div className="landing-security-item">
              <div className="landing-security-corner" />
              <ShieldCheck size={24} strokeWidth={2} />
              <div>
                <h4>Role-Based Access Control</h4>
                <p>Granular permissions ensure users only access functions appropriate to their role.</p>
              </div>
            </div>

            <div className="landing-security-item">
              <div className="landing-security-corner" />
              <Lock size={24} strokeWidth={2} />
              <div>
                <h4>Secure Authentication</h4>
                <p>Encrypted sessions with CSRF protection and secure password handling.</p>
              </div>
            </div>

            <div className="landing-security-item">
              <div className="landing-security-corner" />
              <Activity size={24} strokeWidth={2} />
              <div>
                <h4>Audit Trail</h4>
                <p>Comprehensive logging of all operations for compliance and forensic analysis.</p>
              </div>
            </div>

            <div className="landing-security-item">
              <div className="landing-security-corner" />
              <Shield size={24} strokeWidth={2} />
              <div>
                <h4>Session Management</h4>
                <p>Time-limited sessions with automatic expiration and secure logout.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="landing-cta-section">
        <div className="landing-container">
          <div className="landing-cta-box">
            <div className="landing-cta-decoration" />
            <h2>Ready to Strengthen Your Backup Security?</h2>
            <p>Join ARBR to protect your critical infrastructure with resilient backup and recovery operations.</p>
            <div className="landing-cta-actions">
              <Link to="/register" className="landing-cta landing-cta--primary landing-cta--large">
                Get Started Free <ArrowRight size={20} />
              </Link>
              <Link to="/login" className="landing-cta landing-cta--secondary landing-cta--large">
                Sign In to Your Account
              </Link>
            </div>
          </div>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="landing-container">
          <div className="landing-footer-content">
            <div className="landing-footer-brand">
              <div className="landing-footer-mark">
                <Shield size={20} strokeWidth={2} />
              </div>
              <div>
                <strong>ARBR</strong>
                <span>Attack-Resistant Backup & Recovery</span>
              </div>
            </div>
            <div className="landing-footer-links">
              <Link to="/login">Sign In</Link>
              <Link to="/register">Get Started</Link>
            </div>
          </div>
          <div className="landing-footer-bottom">
            <span>ARBR · 2026</span>
            <span>Defensive Operations Platform</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
