import { useState, useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { signOut } from "firebase/auth";
import { auth, db } from "@/lib/firebase";
import { doc, updateDoc } from "firebase/firestore";
import { Sidebar } from "@/components/Sidebar";
import { ChatArea } from "@/components/ChatArea";
import { SystemNoticeModal } from "@/components/SystemNoticeModal";
import { MessageLimitModal } from "@/components/MessageLimitModal";
import { DisclaimerModal } from "@/components/DisclaimerModal";
import { Menu, Loader2 } from "lucide-react";
import { MessagesService } from "@/lib/messages";
import { toast } from "sonner";

export default function Index() {
  const { loading, userBan, maintenanceNotice, user, userData } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [acknowledgedMaintenance, setAcknowledgedMaintenance] = useState(false);
  const [activeConversationId, setActiveConversationId] = useState<string>();
  const [disclaimerAccepted, setDisclaimerAccepted] = useState(
    userData?.disclaimerAccepted || false,
  );

  useEffect(() => {
    // Load first conversation if available
    if (user?.uid) {
      loadFirstConversation();
    }
  }, [user?.uid]);

  const loadFirstConversation = async () => {
    if (!user?.uid) return;
    try {
      const conversations = await MessagesService.getConversations(user.uid);
      if (conversations.length > 0) {
        setActiveConversationId(conversations[0].id);
      }
    } catch (error) {
      console.error("Error loading first conversation:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
      }
    }
  };

  useEffect(() => {
    // If user is banned, log them out
    if (userBan) {
      signOut(auth).catch(console.error);
    }
  }, [userBan]);

  useEffect(() => {
    // Update disclaimer state when userData changes
    if (userData?.disclaimerAccepted) {
      setDisclaimerAccepted(true);
    }
  }, [userData?.disclaimerAccepted]);

  const handleDisclaimerAccept = async () => {
    try {
      if (user?.uid) {
        const userRef = doc(db, "users", user.uid);
        await updateDoc(userRef, {
          disclaimerAccepted: true,
          disclaimerAcceptedAt: Date.now(),
        });
        setDisclaimerAccepted(true);
      }
    } catch (error) {
      console.error("Error accepting disclaimer:", error);
      toast.error("Erreur lors de l'enregistrement du disclaimer");
    }
  };

  const handleDisclaimerDecline = () => {
    signOut(auth).catch(console.error);
  };

  if (loading) {
    return (
      <div className="flex h-screen bg-background items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-white" />
      </div>
    );
  }

  // Show ban modal (non-dismissible, forces logout)
  if (userBan) {
    return (
      <SystemNoticeModal
        type="ban"
        title="Compte banni"
        message={`Votre compte a été banni pour la raison suivante: "${userBan.reason}"`}
        severity="critical"
        reason={userBan.reason}
        expiresAt={userBan.expiresAt ? userBan.expiresAt.toDate() : undefined}
        dismissible={false}
      />
    );
  }

  // Show message limit modal (non-dismissible)
  if (userData && userData.messagesUsed >= userData.messagesLimit) {
    return (
      <MessageLimitModal
        messagesUsed={userData.messagesUsed}
        messagesLimit={userData.messagesLimit}
      />
    );
  }

  // Show disclaimer modal if not accepted
  if (!disclaimerAccepted) {
    return (
      <DisclaimerModal
        isOpen={true}
        onAccept={handleDisclaimerAccept}
        onDecline={handleDisclaimerDecline}
      />
    );
  }

  // Show maintenance modal (dismissible)
  if (maintenanceNotice && !acknowledgedMaintenance) {
    return (
      <>
        <SystemNoticeModal
          type="maintenance"
          title={maintenanceNotice.title}
          message={maintenanceNotice.message}
          severity={maintenanceNotice.severity}
          onAcknowledge={() => setAcknowledgedMaintenance(true)}
          dismissible={maintenanceNotice.severity !== "critical"}
        />
        {maintenanceNotice.severity !== "critical" && (
          <div className="flex h-screen bg-background opacity-50 pointer-events-none">
            <Sidebar
              isOpen={sidebarOpen}
              onClose={() => setSidebarOpen(false)}
              activeConversationId={activeConversationId}
              onConversationSelect={setActiveConversationId}
            />
            <div className="flex-1 flex flex-col md:flex-row">
              <ChatArea conversationId={activeConversationId} />
            </div>
          </div>
        )}
      </>
    );
  }

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar - Hidden by default, opens as drawer on hamburger click */}
      <Sidebar
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        activeConversationId={activeConversationId}
        onConversationSelect={setActiveConversationId}
      />

      {/* Main Content - Full width */}
      <div className="flex-1 flex flex-col">
        {/* Header with Menu Button */}
        <div className="border-b border-border px-4 md:px-6 py-3 flex items-center justify-between bg-background">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="p-2 hover:bg-secondary rounded-lg transition-all duration-200 text-muted-foreground hover:text-foreground"
            aria-label="Toggle Menu"
            title="Toggle Menu"
          >
            <Menu size={20} />
          </button>

          <div className="flex-1 text-center">
            <h1 className="text-base font-semibold text-foreground">VanIA</h1>
          </div>

          <div className="w-8" />
        </div>

        {/* Chat Area */}
        <ChatArea conversationId={activeConversationId} />
      </div>
    </div>
  );
}
