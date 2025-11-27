import {
  Plus,
  LogOut,
  MoreVertical,
  Trash2,
  Edit2,
  Loader2,
  Shield,
  X,
} from "lucide-react";
import { useState, useEffect } from "react";
import { signOut } from "firebase/auth";
import { auth } from "@/lib/firebase";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { toast } from "sonner";
import { MessagesService } from "@/lib/messages";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { SettingsModal } from "@/components/SettingsModal";
import { HelpModal } from "@/components/HelpModal";

interface Conversation {
  id: string;
  name: string;
  active: boolean;
  isDeleting?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
  messageCount?: number;
}

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
  activeConversationId?: string;
  onConversationSelect?: (id: string) => void;
}

export function Sidebar({
  isOpen = true,
  onClose,
  activeConversationId,
  onConversationSelect,
}: SidebarProps) {
  const { user, userData, loading } = useAuth();
  const { isDark } = useTheme();
  const navigate = useNavigate();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loadingConversations, setLoadingConversations] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isHelpOpen, setIsHelpOpen] = useState(false);
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);

  const userInitial = userData?.displayName?.[0]?.toUpperCase() || "U";
  const messagesUsed = userData?.messagesUsed || 0;
  const messagesLimit = userData?.messagesLimit || 10;

  useEffect(() => {
    if (user?.uid) {
      loadConversations();
    }
  }, [user?.uid]);

  const loadConversations = async () => {
    if (!user?.uid) return;
    try {
      setLoadingConversations(true);
      const fbConversations = await MessagesService.getConversations(user.uid);
      setConversations(
        fbConversations.map((conv) => ({
          id: conv.id,
          name: conv.title,
          active: conv.id === activeConversationId,
          createdAt: conv.createdAt.toDate(),
          updatedAt: conv.updatedAt.toDate(),
          messageCount: conv.messageCount,
        })),
      );
    } catch (error) {
      console.error("Error loading conversations:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        if (error.message.includes("Failed to fetch")) {
          toast.error("Erreur réseau. Vérifiez votre connexion.");
        } else {
          toast.error("Erreur lors du chargement des conversations");
        }
      } else {
        toast.error("Erreur lors du chargement des conversations");
      }
    } finally {
      setLoadingConversations(false);
    }
  };

  const handleNewConversation = async () => {
    if (!user?.uid) return;
    try {
      const conversationRef = await MessagesService.createConversation(
        user.uid,
        "Nouvelle conversation",
      );
      const newConversation: Conversation = {
        id: conversationRef.id,
        name: "Nouvelle conversation",
        active: true,
        createdAt: new Date(),
        updatedAt: new Date(),
        messageCount: 0,
      };
      setConversations([newConversation, ...conversations]);
      onConversationSelect?.(conversationRef.id);
      toast.success("Conversation créée");
    } catch (error) {
      console.error("Error creating conversation:", error);
      toast.error("Erreur lors de la création de la conversation");
    }
  };

  const handleLogout = async () => {
    try {
      await signOut(auth);
      navigate("/login");
      toast.success("Déconnecté avec succès");
    } catch (error) {
      toast.error("Erreur lors de la déconnexion");
    }
  };

  const handleSyncMessages = async () => {
    setIsSyncing(true);
    try {
      await loadConversations();
      toast.success("Messages synchronisés");
    } catch (error) {
      console.error("Error syncing conversations:", error);
      toast.error("Erreur de synchronisation");
    } finally {
      setIsSyncing(false);
    }
  };

  const handleDeleteConversation = async (id: string) => {
    setConversations(
      conversations.map((c) => (c.id === id ? { ...c, isDeleting: true } : c)),
    );
    setTimeout(async () => {
      try {
        await MessagesService.deleteConversation(id);
        setConversations((prev) => prev.filter((c) => c.id !== id));
        setEditingId(null);
        toast.success("Conversation supprimée");
      } catch (error) {
        console.error("Error deleting conversation:", error);
        toast.error("Erreur lors de la suppression");
        await loadConversations();
      }
    }, 300);
  };

  const handleEditConversation = (id: string, currentName: string) => {
    setEditingId(id);
    setEditName(currentName);
    setIsDialogOpen(true);
  };

  const handleSaveEdit = async () => {
    if (!editingId || !editName.trim()) return;

    try {
      await MessagesService.updateConversation(editingId, {
        title: editName,
      });
      setConversations(
        conversations.map((c) =>
          c.id === editingId ? { ...c, name: editName } : c,
        ),
      );
      toast.success("Conversation mise à jour");
    } catch (error) {
      console.error("Error updating conversation:", error);
      toast.error("Erreur lors de la mise à jour");
    } finally {
      setIsDialogOpen(false);
      setEditingId(null);
      setEditName("");
    }
  };

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className={`fixed inset-0 md:hidden transition-colors duration-300 ${
            isDark ? "bg-black/50" : "bg-black/30"
          }`}
          onClick={onClose}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 w-44 sm:w-48 flex flex-col transition-all duration-300 ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        } z-50 animate-slideInLeft ${
          isDark
            ? "bg-sidebar border-r border-white/[0.08]"
            : "bg-[#FFFFFF] border-r border-black/[0.08]"
        }`}
      >
        {/* Header - Minimal */}
        <div
          className={`pt-5 px-3 pb-3 animate-fadeIn border-b transition-all duration-300 ${
            isDark ? "border-white/[0.08]" : "border-black/[0.08]"
          }`}
        >
          <div className="flex items-center gap-2.5 justify-between mb-2.5">
            <button
              onClick={() => setIsSettingsOpen(true)}
              className={`flex items-center gap-2 min-w-0 flex-1 hover:opacity-80 transition-opacity rounded-lg p-1 -m-1 ${
                isDark ? "" : ""
              }`}
            >
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0 shadow-md border transition-all duration-300 ${
                  isDark
                    ? "bg-gradient-to-br from-primary/80 to-primary text-primary-foreground border-primary/30"
                    : "bg-gradient-to-br from-primary/60 to-primary/50 text-white border-primary/40"
                }`}
              >
                {userInitial}
              </div>
              <div className="hidden sm:block min-w-0 flex-1">
                <p
                  className={`text-xs font-medium truncate leading-tight transition-colors duration-300 ${
                    isDark ? "text-foreground" : "text-[#1A1A1A]"
                  }`}
                >
                  {loading ? "..." : userData?.displayName || "User"}
                </p>
                <p
                  className={`text-xs truncate leading-tight transition-colors duration-300 ${
                    isDark ? "text-muted-foreground" : "text-[#3F3F3F]/70"
                  }`}
                >
                  {loading ? "..." : userData?.email?.split("@")[0] || "Pro"}
                </p>
              </div>
            </button>
            <div className="flex items-center gap-1">
              <button
                onClick={onClose}
                className={`p-1.5 rounded-lg transition-all flex-shrink-0 hover:-translate-y-0.5 ${
                  isDark
                    ? "hover:bg-white/[0.08] text-foreground/60 hover:text-foreground"
                    : "hover:bg-black/[0.08] text-[#3F3F3F]/60 hover:text-[#1A1A1A]"
                }`}
                aria-label="Close"
                title="Close"
              >
                <X size={16} />
              </button>
              <Popover open={isMenuOpen} onOpenChange={setIsMenuOpen}>
                <PopoverTrigger asChild>
                  <button
                    className={`p-1.5 rounded-lg transition-all flex-shrink-0 hover:-translate-y-0.5 ${
                      isDark
                        ? "hover:bg-white/[0.08] text-foreground/60 hover:text-foreground"
                        : "hover:bg-black/[0.08] text-[#3F3F3F]/60 hover:text-[#1A1A1A]"
                    }`}
                  >
                    <MoreVertical size={16} />
                  </button>
                </PopoverTrigger>
                <PopoverContent
                  className={`w-40 p-1 border rounded-lg shadow-lg transition-all duration-300 ${
                    isDark
                      ? "bg-card border-white/[0.1]"
                      : "bg-[#FAFAFA] border-black/[0.08]"
                  }`}
                >
                  <div className="space-y-0.5">
                    <button
                      onClick={() => {
                        setIsSettingsOpen(true);
                        setIsMenuOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-all hover:-translate-y-0.5 ${
                        isDark
                          ? "text-foreground/70 hover:text-foreground hover:bg-white/[0.08]"
                          : "text-[#3F3F3F]/70 hover:text-[#1A1A1A] hover:bg-black/[0.08]"
                      }`}
                    >
                      Paramètres
                    </button>
                    <button
                      onClick={() => {
                        setIsHelpOpen(true);
                        setIsMenuOpen(false);
                      }}
                      className={`w-full text-left px-3 py-2 rounded-lg text-xs transition-all hover:-translate-y-0.5 ${
                        isDark
                          ? "text-foreground/70 hover:text-foreground hover:bg-white/[0.08]"
                          : "text-[#3F3F3F]/70 hover:text-[#1A1A1A] hover:bg-black/[0.08]"
                      }`}
                    >
                      Aide
                    </button>
                    {userData?.isAdmin && (
                      <>
                        <div
                          className={`h-px my-0.5 transition-colors duration-300 ${
                            isDark ? "bg-white/[0.08]" : "bg-black/[0.08]"
                          }`}
                        />
                        <button
                          onClick={() => {
                            navigate("/admin");
                            setIsMenuOpen(false);
                          }}
                          className={`w-full text-left px-3 py-2 rounded-lg text-xs font-medium transition-all hover:-translate-y-0.5 text-primary ${
                            isDark
                              ? "hover:bg-white/[0.08]"
                              : "hover:bg-black/[0.08]"
                          }`}
                        >
                          Admin
                        </button>
                      </>
                    )}
                  </div>
                </PopoverContent>
              </Popover>
            </div>
          </div>
          <p
            className={`text-xs truncate hidden sm:block transition-colors duration-300 ${
              isDark ? "text-foreground/50" : "text-[#3F3F3F]/50"
            }`}
          >
            {loading ? "..." : userData?.email}
          </p>
        </div>

        {/* New Conversation Button */}
        <div
          className="px-3 py-4 animate-fadeIn"
          style={{ animationDelay: "0.1s" }}
        >
          <button
            id="new-conversation-btn"
            onClick={handleNewConversation}
            className={`w-full flex items-center justify-center gap-2 px-3 py-2 font-medium text-xs rounded-lg transition-all duration-200 shadow-sm hover:shadow-md hover:opacity-95 hover:-translate-y-px active:scale-95 ${
              isDark
                ? "bg-primary/20 hover:bg-primary/30 text-primary"
                : "bg-primary/10 hover:bg-primary/20 text-primary"
            }`}
          >
            <Plus size={16} className="flex-shrink-0" />
            <span>New</span>
          </button>
        </div>

        {/* Conversations List */}
        <div
          id="conversations-list"
          className="flex-1 overflow-y-auto px-3 py-2"
        >
          <div className="space-y-2">
            {conversations.map((conv, idx) => (
              <div
                key={conv.id}
                className="group transition-all duration-300"
                style={{
                  animationDelay: `${0.2 + idx * 0.05}s`,
                  opacity: conv.isDeleting ? 0 : 1,
                  transform: conv.isDeleting
                    ? "translateX(-10px)"
                    : "translateX(0)",
                }}
              >
                <div
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg transition-all border shadow-sm group-hover:-translate-y-px ${
                    conv.id === activeConversationId
                      ? isDark
                        ? "bg-primary/15 border-primary/50 text-foreground shadow-md"
                        : "bg-primary/10 border-primary/30 text-[#1A1A1A] shadow-md"
                      : isDark
                        ? "border-white/[0.08] hover:bg-white/[0.05] text-muted-foreground hover:text-foreground hover:shadow-md hover:border-primary/30"
                        : "border-black/[0.08] hover:bg-black/[0.05] text-[#3F3F3F]/70 hover:text-[#1A1A1A] hover:shadow-md hover:border-primary/30"
                  }`}
                >
                  <button
                    onClick={() => onConversationSelect?.(conv.id)}
                    className={`flex-1 text-left text-xs transition-all py-1 px-1 rounded-lg truncate ${
                      conv.id === activeConversationId
                        ? isDark
                          ? "text-foreground font-medium"
                          : "text-[#1A1A1A] font-medium"
                        : isDark
                          ? "text-foreground/70 hover:text-foreground"
                          : "text-[#3F3F3F]/70 hover:text-[#1A1A1A]"
                    }`}
                  >
                    {conv.name}
                  </button>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => handleEditConversation(conv.id, conv.name)}
                      className={`p-1.5 rounded-lg transition-all hover:-translate-y-0.5 ${
                        isDark
                          ? "text-foreground/60 hover:text-foreground hover:bg-white/10"
                          : "text-[#3F3F3F]/60 hover:text-[#1A1A1A] hover:bg-black/[0.08]"
                      }`}
                      title="Edit"
                    >
                      <Edit2 size={14} />
                    </button>
                    <button
                      onClick={() => handleDeleteConversation(conv.id)}
                      className={`p-1.5 rounded-lg transition-all hover:-translate-y-0.5 ${
                        isDark
                          ? "text-foreground/60 hover:text-red-400 hover:bg-red-500/10"
                          : "text-[#3F3F3F]/60 hover:text-red-600 hover:bg-red-100/50"
                      }`}
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Message Usage Section */}
        <div
          id="messages-counter"
          className={`px-3 py-2.5 border-t animate-fadeIn rounded-[10px] shadow-sm transition-all duration-300 ${
            isDark
              ? "border-white/[0.08] bg-white/[0.02]"
              : "border-black/[0.08] bg-black/[0.02]"
          }`}
          style={{
            animationDelay: "0.25s",
            marginLeft: "20px",
            marginTop: "16px",
            marginBottom: "22px",
            maxWidth: "calc(100% - 40px)",
          }}
        >
          <div className="flex items-center gap-2 mb-2.5 justify-between">
            <span
              className={`text-xs font-medium transition-colors duration-300 ${
                isDark ? "text-foreground/70" : "text-[#3F3F3F]/70"
              }`}
            >
              Messages
            </span>
            <button
              onClick={handleSyncMessages}
              disabled={isSyncing}
              className={`p-1.5 rounded-lg transition-all disabled:opacity-50 hover:-translate-y-0.5 ${
                isDark ? "hover:bg-white/10" : "hover:bg-black/[0.08]"
              }`}
              title="Synchroniser"
            >
              {isSyncing ? (
                <Loader2
                  size={14}
                  className={`animate-spin transition-colors duration-300 ${
                    isDark ? "text-foreground/60" : "text-[#3F3F3F]/60"
                  }`}
                />
              ) : (
                <svg
                  className={`w-4 h-4 transition-colors duration-300 ${
                    isDark
                      ? "text-foreground/60 hover:text-foreground"
                      : "text-[#3F3F3F]/60 hover:text-[#1A1A1A]"
                  }`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                  />
                </svg>
              )}
            </button>
          </div>
          <div className="space-y-1.5">
            <div
              className={`relative h-2 rounded-full overflow-hidden transition-colors duration-300 ${
                isDark ? "bg-white/[0.08]" : "bg-black/[0.08]"
              }`}
            >
              <div
                className="h-full bg-gradient-to-r from-primary/60 to-primary/80 rounded-full transition-all shadow-sm"
                style={{ width: `${(messagesUsed / messagesLimit) * 100}%` }}
              ></div>
            </div>
            <p
              className={`text-xs transition-colors duration-300 ${
                isDark ? "text-foreground/60" : "text-[#3F3F3F]/60"
              }`}
            >
              {messagesLimit - messagesUsed} sur {messagesLimit} restants
            </p>
          </div>
        </div>

        {/* Footer - Sign Out */}
        <div
          className={`px-3 py-4 border-t animate-fadeIn transition-all duration-300 ${
            isDark ? "border-white/[0.08]" : "border-black/[0.08]"
          }`}
          style={{ animationDelay: "0.3s" }}
        >
          <button
            onClick={handleLogout}
            className={`w-full flex items-center justify-center gap-2 px-3 py-2 border transition-all text-xs font-medium rounded-lg hover:opacity-95 hover:-translate-y-px active:scale-95 shadow-sm hover:shadow-md ${
              isDark
                ? "text-red-400/80 hover:text-red-400 border-red-500/30 hover:border-red-500/50 hover:bg-red-500/10"
                : "text-red-600/80 hover:text-red-700 border-red-300/50 hover:border-red-400/50 hover:bg-red-100/50"
            }`}
          >
            <LogOut size={16} />
            <span>Se déconnecter</span>
          </button>
        </div>
      </aside>

      {/* Edit Conversation Modal */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent
          className={`border rounded-xl transition-all duration-300 ${
            isDark
              ? "bg-card border-white/[0.1]"
              : "bg-[#FAFAFA] border-black/[0.08]"
          }`}
        >
          <DialogHeader>
            <DialogTitle
              className={`text-lg font-semibold transition-colors duration-300 ${
                isDark ? "text-foreground" : "text-[#1A1A1A]"
              }`}
            >
              Modifier la Conversation
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <input
              type="text"
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              placeholder="Nom de la conversation..."
              className={`w-full border rounded-lg px-4 py-2.5 focus:outline-none transition-all text-sm ${
                isDark
                  ? "bg-white/[0.02] border-white/[0.1] text-foreground placeholder-foreground/40 focus:border-primary/50 focus:bg-white/[0.05]"
                  : "bg-[#FFFFFF] border-black/[0.08] text-[#1A1A1A] placeholder-[#3F3F3F]/40 focus:border-primary/50 focus:bg-[#FFFFFF]"
              }`}
              onKeyPress={(e) => {
                if (e.key === "Enter") {
                  handleSaveEdit();
                }
              }}
              autoFocus
            />
          </div>
          <DialogFooter className="gap-2">
            <button
              onClick={() => setIsDialogOpen(false)}
              className={`px-4 py-2.5 border rounded-lg transition-all text-sm font-medium hover:-translate-y-0.5 ${
                isDark
                  ? "text-foreground/70 border-white/[0.1] hover:bg-white/[0.05]"
                  : "text-[#3F3F3F]/70 border-black/[0.08] hover:bg-black/[0.05]"
              }`}
            >
              Annuler
            </button>
            <button
              onClick={handleSaveEdit}
              className={`px-4 py-2.5 border rounded-lg transition-all font-medium text-sm hover:-translate-y-0.5 ${
                isDark
                  ? "bg-primary/20 text-primary border-primary/30 hover:bg-primary/30"
                  : "bg-primary/10 text-primary border-primary/30 hover:bg-primary/20"
              }`}
            >
              Enregistrer
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Settings Modal */}
      <SettingsModal isOpen={isSettingsOpen} onOpenChange={setIsSettingsOpen} />

      {/* Help Modal */}
      <HelpModal isOpen={isHelpOpen} onOpenChange={setIsHelpOpen} />
    </>
  );
}
