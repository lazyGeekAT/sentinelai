import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useBehavioral } from '../sdk/behavioral';
import { Shield, Lock, Mail, ArrowRight } from 'lucide-react';
import { api, setUserSession, isAdmin } from '../lib/api';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [otpSessionId, setOtpSessionId] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [captchaToken, setCaptchaToken] = useState('');
  const [captchaPrompt, setCaptchaPrompt] = useState('');
  const [captchaAnswer, setCaptchaAnswer] = useState('');
  const [requiresOtp, setRequiresOtp] = useState(false);
  const [requiresCaptcha, setRequiresCaptcha] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const navigate = useNavigate();
  const getBehavioralPayload = useBehavioral();

  const handleLogin = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setInfo('');
    
    const behavioralData = getBehavioralPayload();

    try {
      const response = await api.post('/login', {
        email,
        password,
        behavioralData,
        ip_address: '127.0.0.1',
        user_agent: navigator.userAgent,
        country: 'US',
      });

      if (response.data.otp_required) {
        setRequiresOtp(true);
        setOtpSessionId(response.data.otp_session_id);
        setInfo('OTP is required. We sent a code to your account session.');

        if (response.data.otp_session_id) {
          await api.post('/otp/send', {
            otp_session_id: response.data.otp_session_id,
            email,
          });
        }
      } else if (response.data.captcha_required) {
        setRequiresCaptcha(true);
        setCaptchaToken(response.data.captcha_token);
        setCaptchaPrompt(response.data.captcha_prompt);
        setInfo('Captcha verification is required.');
      } else       if (response.data.token) {
        setUserSession({ token: response.data.token, userId: response.data.user_id });
        const isAdminUser = isAdmin();
        navigate(isAdminUser ? '/dashboard' : '/events', { replace: true });
      }
    } catch (err) {
      setError(err?.response?.data?.detail || 'Login failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleOtpVerify = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await api.post('/otp/verify', {
        otp_session_id: otpSessionId,
        otp_code: otpCode,
      });

      setUserSession({ token: response.data.token, userId: response.data.user_id });
      navigate(isAdmin() ? '/dashboard' : '/events', { replace: true });
    } catch (err) {
      setError(err?.response?.data?.detail || 'OTP verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCaptchaVerify = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const response = await api.post('/captcha/verify', {
        captcha_token: captchaToken,
        captcha_answer: captchaAnswer,
      });

      setUserSession({ token: response.data.token, userId: response.data.user_id });
      navigate(isAdmin() ? '/dashboard' : '/events', { replace: true });
    } catch (err) {
      setError(err?.response?.data?.detail || 'Captcha verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Dynamic Background */}
      <div className="absolute inset-0 z-0 overflow-hidden">
        <div className="absolute top-[-20%] left-[-10%] w-[50%] h-[50%] bg-blue-500/20 blur-[120px] rounded-full"></div>
        <div className="absolute bottom-[-20%] right-[-10%] w-[50%] h-[50%] bg-purple-500/20 blur-[120px] rounded-full"></div>
      </div>

      <div className="z-10 w-full max-w-md bg-gray-800/50 backdrop-blur-xl border border-gray-700 p-8 rounded-2xl shadow-2xl">
        <div className="flex flex-col items-center mb-8">
          <div className="bg-blue-500/20 p-3 rounded-full mb-4 ring-1 ring-blue-500/50">
            <Shield className="w-8 h-8 text-blue-400" />
          </div>
          <h1 className="text-3xl font-bold text-white tracking-tight">SentinelAI</h1>
          <p className="text-gray-400 mt-2 text-sm text-center">
            Behavioral Intelligence Platform
          </p>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
            {error}
          </div>
        )}

        {info && (
          <div className="mb-4 rounded-lg border border-blue-500/30 bg-blue-500/10 px-4 py-3 text-sm text-blue-200">
            {info}
          </div>
        )}

        {!requiresOtp && !requiresCaptcha ? (
          <form onSubmit={handleLogin} className="space-y-6">
          <div className="space-y-1">
            <label className="text-sm font-medium text-gray-300">Email Address</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Mail className="h-5 w-5 text-gray-500" />
              </div>
              <input
                type="email"
                required
                className="w-full bg-gray-900/50 border border-gray-700 text-white rounded-lg pl-10 pr-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
                placeholder="admin@sentinelai.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium text-gray-300">Password</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Lock className="h-5 w-5 text-gray-500" />
              </div>
              <input
                type="password"
                required
                className="w-full bg-gray-900/50 border border-gray-700 text-white rounded-lg pl-10 pr-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all"
                placeholder="••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold rounded-lg py-2.5 px-4 flex items-center justify-center space-x-2 transition-all transform hover:scale-[1.02] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-blue-500/50 disabled:opacity-70 disabled:cursor-not-allowed"
          >
            {isLoading ? (
              <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
            ) : (
              <>
                <span>Secure Login</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
          </form>
        ) : requiresOtp ? (
          <form onSubmit={handleOtpVerify} className="space-y-6">
            <div className="space-y-1">
              <label className="text-sm font-medium text-gray-300">OTP Code</label>
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                required
                className="w-full bg-gray-900/50 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all tracking-[0.3em] text-center"
                placeholder="123456"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold rounded-lg py-2.5 px-4 flex items-center justify-center space-x-2 transition-all transform hover:scale-[1.02] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-emerald-500/50 disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
              ) : (
                <>
                  <span>Verify OTP</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        ) : (
          <form onSubmit={handleCaptchaVerify} className="space-y-6">
            <div className="space-y-1">
              <label className="text-sm font-medium text-gray-300">Captcha Challenge</label>
              <div className="rounded-lg border border-gray-700 bg-gray-900/50 px-4 py-3 text-center tracking-[0.4em] text-lg font-semibold text-blue-300">
                {captchaPrompt || 'Loading...'}
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-sm font-medium text-gray-300">Enter the code above</label>
              <input
                type="text"
                required
                className="w-full bg-gray-900/50 border border-gray-700 text-white rounded-lg px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500 transition-all tracking-[0.3em] text-center uppercase"
                placeholder="ABC123"
                value={captchaAnswer}
                onChange={(e) => setCaptchaAnswer(e.target.value)}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white font-semibold rounded-lg py-2.5 px-4 flex items-center justify-center space-x-2 transition-all transform hover:scale-[1.02] active:scale-[0.98] focus:outline-none focus:ring-2 focus:ring-amber-500/50 disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
              ) : (
                <>
                  <span>Verify Captcha</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}

        <div className="mt-6 text-center text-sm text-gray-400">
          New to SentinelAI?{' '}
          <Link to="/register" className="text-blue-400 hover:text-blue-300 font-medium transition-colors">
            Register Account
          </Link>
        </div>
      </div>
      
      {/* Demo helper */}
      <div className="mt-8 text-xs text-gray-500 z-10 flex items-center gap-2">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
        </span>
        Behavioral SDK Active
      </div>
    </div>
  );
}
