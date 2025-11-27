import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useState, useEffect } from "react";
import { Moon, LogOut, Loader2, Sun } from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { ProfilePhotoUpload } from "@/components/ProfilePhotoUpload";
import { doc, updateDoc } from "firebase/firestore";
import { db } from "@/lib/firebase";
import { signOut } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

interface SettingsModalProps {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SettingsModal({ isOpen, onOpenChange }: SettingsModalProps) {
  const { user, userData } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  useEffect(() => {
    if (userData?.displayName) {
      setDisplayName(userData.displayName);
    }
  }, [userData?.displayName, isOpen]);

  const handleDisplayNameChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.slice(0, 10);
    setDisplayName(value);
    setHasChanges(true);
  };

  const handleDarkModeToggle = async () => {
    try {
      toggleTheme();
      toast.success(!isDark ? "Mode sombre activé" : "Mode clair activé");
    } catch (error) {
      console.error("Error toggling dark mode:", error);
      toast.error("Erreur lors du changement de mode");
    }
  };

  const handleSaveChanges = async () => {
    if (!user?.uid || !displayName.trim()) {
      toast.error("Le pseudo ne peut pas être vide");
      return;
    }

    try {
      setIsSaving(true);
      const userRef = doc(db, "users", user.uid);
      await updateDoc(userRef, {
        displayName: displayName.trim(),
      });
      setHasChanges(false);
      setSaveSuccess(true);
      toast.success("Paramètres sauvegardés");

      setTimeout(() => setSaveSuccess(false), 2000);
    } catch (error) {
      console.error("Error saving settings:", error);
      toast.error("Erreur lors de la sauvegarde");
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      navigate("/login");
      onOpenChange(false);
      toast.success("Déconnecté avec succès");
    } catch (error) {
      console.error("Error logging out:", error);
      toast.error("Erreur lors de la déconnexion");
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onOpenChange}>
      <DialogContent
        className={`border-0 rounded-[12px] w-[460px] max-h-[85vh] flex flex-col p-0 overflow-hidden shadow-2xl transition-all duration-300 ${
          isDark ? "bg-[#0f0f0f]" : "bg-[#FAFAFA] border border-black/5"
        }`}
      >
        {/* Header */}
        <DialogHeader
          className={`px-6 py-4 border-b transition-all duration-300 ${
            isDark ? "border-white/[0.06]" : "border-black/[0.08]"
          }`}
        >
          <DialogTitle
            className={`text-lg font-semibold transition-colors duration-300 ${
              isDark ? "text-foreground" : "text-[#1A1A1A]"
            }`}
          >
            Paramètres
          </DialogTitle>
        </DialogHeader>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          <div className="space-y-5">
            {/* Section 1: Profile Photo */}
            {user?.uid && (
              <div
                className="animate-fadeIn"
                style={{ animationDelay: "0.05s" }}
              >
                <h3
                  className={`text-xs font-semibold uppercase tracking-wider mb-3 transition-colors duration-300 ${
                    isDark ? "text-foreground/80" : "text-[#3F3F3F]/70"
                  }`}
                >
                  Photo de profil
                </h3>
                <div
                  className={`rounded-[10px] p-4 shadow-sm transition-all duration-300 ${
                    isDark
                      ? "bg-white/[0.03]"
                      : "bg-[#FFFFFF] border border-black/[0.08]"
                  }`}
                >
                  <ProfilePhotoUpload
                    userId={user.uid}
                    currentPhotoUrl={
                      userData?.profilePhotoURL || user.photoURL || undefined
                    }
                    displayName={
                      userData?.displayName || user.displayName || "User"
                    }
                  />
                </div>
              </div>
            )}

            {/* Section 2: Display Name / Pseudo */}
            <div className="animate-fadeIn" style={{ animationDelay: "0.1s" }}>
              <h3
                className={`text-xs font-semibold uppercase tracking-wider mb-3 transition-colors duration-300 ${
                  isDark ? "text-foreground/80" : "text-[#3F3F3F]/70"
                }`}
              >
                Pseudo
              </h3>
              <div className="space-y-2">
                <input
                  type="text"
                  value={displayName}
                  onChange={handleDisplayNameChange}
                  placeholder="Votre pseudo..."
                  maxLength={10}
                  className={`w-full border rounded-[10px] px-3 py-2.5 placeholder-opacity-50 focus:outline-none transition-all duration-200 text-sm ${
                    isDark
                      ? "bg-white/[0.03] border-white/[0.06] text-foreground placeholder-foreground/40 focus:border-primary/40 focus:bg-white/[0.05]"
                      : "bg-[#FFFFFF] border-black/[0.08] text-[#1A1A1A] placeholder-[#3F3F3F]/50 focus:border-primary/40 focus:bg-[#FFFFFF]"
                  }`}
                />
                <div className="flex items-center justify-between px-0.5">
                  <p
                    className={`text-xs transition-colors duration-300 ${
                      isDark ? "text-foreground/50" : "text-[#3F3F3F]/60"
                    }`}
                  >
                    Max 10 caractères
                  </p>
                  <span
                    className={`text-xs transition-colors duration-300 ${
                      isDark ? "text-foreground/40" : "text-[#3F3F3F]/50"
                    }`}
                  >
                    {displayName.length}/10
                  </span>
                </div>
              </div>
            </div>

            {/* Section 3: Dark Mode */}
            <div className="animate-fadeIn" style={{ animationDelay: "0.15s" }}>
              <h3
                className={`text-xs font-semibold uppercase tracking-wider mb-3 transition-colors duration-300 ${
                  isDark ? "text-foreground/80" : "text-[#3F3F3F]/70"
                }`}
              >
                Apparence
              </h3>
              <div
                className={`rounded-[10px] p-3.5 flex items-center justify-between shadow-sm transition-all duration-300 ${
                  isDark
                    ? "bg-white/[0.03]"
                    : "bg-[#FFFFFF] border border-black/[0.08]"
                }`}
              >
                <div>
                  <p
                    className={`text-sm font-medium transition-colors duration-300 ${
                      isDark ? "text-foreground" : "text-[#1A1A1A]"
                    }`}
                  >
                    Mode sombre
                  </p>
                </div>

                {/* iOS 17 Style Toggle */}
                <button
                  onClick={handleDarkModeToggle}
                  className={`relative w-12 h-7 rounded-full transition-all duration-300 flex items-center ${
                    isDark ? "bg-primary/40" : "bg-primary/20"
                  }`}
                >
                  <div
                    className={`absolute w-6 h-6 rounded-full shadow-md transition-all duration-300 flex items-center justify-center ${
                      isDark
                        ? "bg-white translate-x-5"
                        : "bg-white translate-x-0.5"
                    }`}
                  >
                    {isDark ? (
                      <Moon size={14} className="text-primary" />
                    ) : (
                      <Sun size={14} className="text-yellow-500" />
                    )}
                  </div>
                </button>
              </div>
            </div>

            {/* Section 4: Email Display */}
            <div className="animate-fadeIn" style={{ animationDelay: "0.2s" }}>
              <h3
                className={`text-xs font-semibold uppercase tracking-wider mb-3 transition-colors duration-300 ${
                  isDark ? "text-foreground/80" : "text-[#3F3F3F]/70"
                }`}
              >
                Compte
              </h3>
              <div
                className={`rounded-[10px] p-3.5 shadow-sm transition-all duration-300 ${
                  isDark
                    ? "bg-white/[0.03]"
                    : "bg-[#FFFFFF] border border-black/[0.08]"
                }`}
              >
                <p
                  className={`text-xs mb-1 transition-colors duration-300 ${
                    isDark ? "text-foreground/50" : "text-[#3F3F3F]/50"
                  }`}
                >
                  Adresse e-mail
                </p>
                <p
                  className={`text-sm truncate transition-colors duration-300 ${
                    isDark ? "text-foreground" : "text-[#1A1A1A]"
                  }`}
                >
                  {user?.email || "..."}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Sticky Footer with Buttons */}
        <div
          className={`border-t px-6 py-4 space-y-2.5 backdrop-blur-sm transition-all duration-300 ${
            isDark
              ? "border-white/[0.06] bg-[#0a0a0a]/50"
              : "border-black/[0.08] bg-white/40"
          }`}
        >
          <button
            onClick={handleSaveChanges}
            disabled={!hasChanges || isSaving}
            className={`w-full px-4 py-3 font-medium text-sm rounded-[10px] transition-all duration-300 flex items-center justify-center gap-2 ${
              saveSuccess
                ? isDark
                  ? "bg-green-500/20 text-green-400 border border-green-500/30"
                  : "bg-green-100 text-green-700 border border-green-300"
                : isDark
                  ? "bg-primary/20 hover:bg-primary/30 text-primary border border-primary/30 hover:border-primary/50 disabled:opacity-50 disabled:cursor-not-allowed"
                  : "bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 hover:border-primary/50 disabled:opacity-50 disabled:cursor-not-allowed"
            }`}
          >
            {isSaving ? (
              <>
                <Loader2 size={16} className="animate-spin" />
                <span>Enregistrement...</span>
              </>
            ) : saveSuccess ? (
              <>
                <span>✓</span>
                <span>Enregistré</span>
              </>
            ) : (
              "Enregistrer"
            )}
          </button>

          <button
            onClick={handleLogout}
            className={`w-full px-4 py-3 font-medium text-sm rounded-[10px] transition-all duration-300 flex items-center justify-center gap-2 hover:shadow-sm ${
              isDark
                ? "bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 hover:border-red-500/50"
                : "bg-red-100 hover:bg-red-200 text-red-700 border border-red-300 hover:border-red-400"
            }`}
          >
            <LogOut size={16} />
            <span>Se déconnecter</span>
          </button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
