import { Send, Smile, Loader2 } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { MessagesService, Message } from "@/lib/messages";
import { getStorage, ref, getBytes } from "firebase/storage";
import { AIService } from "@/lib/ai";
import {
  validateMessageContent,
  detectInjectionAttempt,
  sanitizeInput,
  RateLimiter,
  escapeHtml,
} from "@/lib/security";
import { toast } from "sonner";
import { MessageRenderer } from "@/components/MessageRenderer";
import { ThinkingAnimation } from "@/components/ThinkingAnimation";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";

const EMOJIS = [
  "😀",
  "😂",
  "😍",
  "🥰",
  "😎",
  "🤔",
  "😢",
  "😡",
  "🎉",
  "🔥",
  "����",
  "❤️",
  "✨",
  "🚀",
  "���",
];

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: number;
}

interface ChatAreaProps {
  conversationId?: string;
}

export function ChatArea({ conversationId }: ChatAreaProps) {
  const { user, userData } = useAuth();
  const [message, setMessage] = useState("");
  const [emojiOpen, setEmojiOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [generatingImage, setGeneratingImage] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Rate limiter: max 30 messages per minute
  const messageRateLimiter = useRef(new RateLimiter("send_message", 30, 60000));

  useEffect(() => {
    if (conversationId && user?.uid) {
      loadMessages();
    }
  }, [conversationId, user?.uid]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, loading, isThinking]);

  const loadMessages = async () => {
    if (!conversationId) return;
    try {
      setLoadingMessages(true);
      const fbMessages = await MessagesService.getMessages(conversationId);
      const messages: ChatMessage[] = fbMessages.map((msg) => ({
        id: msg.id,
        role: msg.text.startsWith("user:") ? "user" : "assistant",
        content: msg.text.replace(/^(user:|assistant:)/, ""),
        timestamp: msg.createdAt.toDate().getTime(),
      }));
      setChatMessages(messages);
    } catch (error) {
      console.error("Error loading messages:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        if (error.message.includes("Failed to fetch")) {
          toast.error("Erreur réseau. Vérifiez votre connexion.");
        } else {
          toast.error("Erreur lors du chargement des messages");
        }
      } else {
        toast.error("Erreur lors du chargement des messages");
      }
    } finally {
      setLoadingMessages(false);
    }
  };

  const handleSend = async () => {
    if (!message.trim() || !user || !userData || !conversationId) return;

    // Rate limiting check
    if (!messageRateLimiter.current.isAllowed()) {
      toast.error(
        "Trop de messages. Veuillez attendre avant d'envoyer un nouveau message.",
      );
      return;
    }

    // Validate message content
    if (!validateMessageContent(message)) {
      toast.error("Message invalide. Longueur: 1-5000 caractères.");
      return;
    }

    // Detect injection attempts
    if (detectInjectionAttempt(message)) {
      toast.error("Message contains invalid characters or patterns.");
      return;
    }

    // Check message limit
    if (userData.messagesUsed >= userData.messagesLimit) {
      toast.error(
        "Limite de messages atteinte. Vous serez redirigé pour activer une licence.",
      );
      return;
    }

    // Warn when getting close to limit (90%)
    const percentUsed = (userData.messagesUsed / userData.messagesLimit) * 100;
    if (percentUsed >= 90) {
      toast.warning(
        `Attention: ${userData.messagesLimit - userData.messagesUsed} messages restants`,
      );
    }

    // Sanitize message
    const sanitizedMessage = sanitizeInput(message.trim());
    const userMessageText = sanitizedMessage;
    const isImage = isImageRequest(userMessageText);
    setMessage("");
    setLoading(true);
    if (!isImage) setIsThinking(true);
    if (isImage) setGeneratingImage(true);

    try {
      // Add user message to chat
      const userMsg: ChatMessage = {
        id: Date.now().toString(),
        role: "user",
        content: userMessageText,
        timestamp: Date.now(),
      };
      setChatMessages((prev) => [...prev, userMsg]);

      // Save user message to Firebase
      await MessagesService.addMessage(
        conversationId,
        user.uid,
        `user:${userMessageText}`,
      );

      let assistantContent: string;

      if (isImage) {
        // Generate image
        assistantContent = await generateImage(userMessageText);
      } else {
        // Get AI response for normal chat
        const conversationHistory = chatMessages.map((msg) => ({
          role: msg.role,
          content: msg.content,
        }));

        setIsThinking(false);
        assistantContent = await AIService.sendMessage(
          userMessageText,
          conversationHistory,
        );
      }

      // Add assistant response to chat
      const assistantMsg: ChatMessage = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: assistantContent,
        timestamp: Date.now(),
      };
      setChatMessages((prev) => [...prev, assistantMsg]);

      // Save assistant message to Firebase
      await MessagesService.addMessage(
        conversationId,
        user.uid,
        `assistant:${assistantContent}`,
      );

      // Update message count in Firebase
      await MessagesService.updateUserMessageCount(
        user.uid,
        userData.messagesUsed + 1,
      );

      if (isImage) {
        toast.success("Image générée avec succès!");
      }
    } catch (error) {
      console.error("Error sending message:", error);
      toast.error(
        error instanceof Error ? error.message : "Erreur lors de l'envoi",
      );
    } finally {
      setLoading(false);
      setIsThinking(false);
      setGeneratingImage(false);
    }
  };

  const addEmoji = (emoji: string) => {
    setMessage(message + emoji);
    setEmojiOpen(false);
  };

  const isImageRequest = (text: string): boolean => {
    const imageKeywords = [
      "crée moi une image",
      "génère une image",
      "generate an image",
      "create an image",
      "dessine",
      "draw",
      "peint",
      "paint",
      "image de",
      "image du",
      "image d",
      "picture of",
      "photo of",
      "visual of",
    ];
    const lowerText = text.toLowerCase();
    return imageKeywords.some((keyword) => lowerText.includes(keyword));
  };

  const generateImage = async (prompt: string): Promise<string> => {
    try {
      // Use Pollinations.ai for image generation
      const imageUrl = `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}`;
      return imageUrl;
    } catch (error) {
      console.error("Error generating image:", error);
      throw new Error("Erreur lors de la génération d'image");
    }
  };

  return (
    <div
      id="chat-area"
      className="flex-1 flex flex-col bg-gradient-to-b from-background via-background to-background/95 min-h-0"
    >
      {/* Main Content Area - Messages Container with Fixed Height & Scrollbar */}
      <div className="flex-1 overflow-y-auto flex flex-col px-4 sm:px-6 md:px-8 py-4 sm:py-6 animate-fadeIn space-y-4 sm:space-y-6 min-h-0">
        {!conversationId ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div
                className="w-20 h-20 rounded-full mx-auto mb-6 flex items-center justify-center border-2 border-foreground/20 animate-scaleIn"
                style={{
                  backgroundImage:
                    "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                  backgroundRepeat: "no-repeat",
                  backgroundPosition: "center",
                  backgroundSize: "cover",
                }}
              />
              <h2 className="text-lg font-semibold text-foreground mb-2 animate-slideUp">
                Sélectionnez une conversation
              </h2>
              <p
                className="text-sm text-foreground/60 animate-slideUp"
                style={{ animationDelay: "0.1s" }}
              >
                Cliquez sur une conversation à gauche pour commencer
              </p>
            </div>
          </div>
        ) : loadingMessages ? (
          <div className="flex-1 flex items-center justify-center">
            <Loader2 className="w-8 h-8 animate-spin text-foreground/50" />
          </div>
        ) : chatMessages.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <div
                className="w-20 h-20 rounded-full mx-auto mb-6 flex items-center justify-center border-2 border-foreground/20 animate-scaleIn"
                style={{
                  backgroundImage:
                    "url(https://cdn.builder.io/api/v1/image/assets%2Fafa67d28f8874020a08a6dc1ed05801d%2F340d671f0c4b45db8b30096668d2bc7c)",
                  backgroundRepeat: "no-repeat",
                  backgroundPosition: "center",
                  backgroundSize: "cover",
                }}
              />
              <h2 className="text-lg font-semibold text-foreground mb-2 animate-slideUp">
                Commencez une conversation
              </h2>
              <p
                className="text-sm text-foreground/60 animate-slideUp"
                style={{ animationDelay: "0.1s" }}
              >
                Tapez un message ci-dessous pour commencer
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6 pb-4">
            {chatMessages.map((msg) => (
              <div
                key={msg.id}
                className={`flex ${
                  msg.role === "user" ? "justify-end" : "justify-start"
                } animate-slideUp`}
              >
                {msg.role === "user" ? (
                  <div className="flex gap-2 sm:gap-3 max-w-xs sm:max-w-sm md:max-w-lg lg:max-w-2xl items-start flex-row-reverse">
                    <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-primary flex items-center justify-center flex-shrink-0 mt-1 overflow-hidden">
                      {userData?.profilePhotoURL ? (
                        <img
                          src={userData.profilePhotoURL}
                          alt={user?.displayName || "User"}
                          className="w-full h-full object-cover"
                        />
                      ) : user?.photoURL ? (
                        <img
                          src={user.photoURL}
                          alt={user.displayName || "User"}
                          className="w-full h-full object-cover"
                        />
                      ) : (
                        <span className="text-xs font-bold text-white">
                          {user?.displayName?.[0]?.toUpperCase() || "U"}
                        </span>
                      )}
                    </div>
                    <div className="flex-1 max-w-xs sm:max-w-sm md:max-w-lg max-h-96 overflow-y-auto">
                      <div className="rounded-xl rounded-tr-none bg-primary text-primary-foreground px-4 py-2.5 text-sm leading-relaxed break-words">
                        <MessageRenderer
                          content={msg.content}
                          role={msg.role}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex gap-2 sm:gap-3 max-w-xs sm:max-w-sm md:max-w-lg lg:max-w-2xl items-start">
                    <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 mt-1">
                      <span className="text-xs font-bold text-secondary-foreground">V</span>
                    </div>
                    <div className="flex-1 max-w-xs sm:max-w-sm md:max-w-lg max-h-96 overflow-y-auto">
                      <div className="rounded-xl rounded-tl-none bg-secondary text-secondary-foreground px-4 py-2.5 text-sm leading-relaxed break-words">
                        <MessageRenderer
                          content={msg.content}
                          role={msg.role}
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
            {(loading || isThinking) && (
              <div className="flex justify-start animate-slideUp">
                <div className="flex gap-2 items-start">
                  <div className="w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-secondary flex items-center justify-center flex-shrink-0 mt-1">
                    <span className="text-xs font-bold text-secondary-foreground">V</span>
                  </div>
                  <ThinkingAnimation />
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Message Input Area - Fixed at Bottom */}
      <div
        className="px-4 sm:px-6 md:px-8 py-4 sm:py-5 animate-slideUp border-t border-border bg-background"
        style={{ animationDelay: "0.2s" }}
      >
        <div
          className={`flex items-center gap-2 border border-border rounded-xl px-4 py-3 bg-card transition-all duration-200 group ${!conversationId ? "opacity-50 cursor-not-allowed" : "hover:border-primary/50 focus-within:border-primary focus-within:ring-1 focus-within:ring-primary/20"}`}
        >
          <input
            id="message-input"
            type="text"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                handleSend();
              }
            }}
            disabled={!conversationId || loading}
            placeholder={
              conversationId
                ? "Votre message..."
                : "Sélectionnez une conversation..."
            }
            className="flex-1 bg-transparent text-foreground placeholder-muted-foreground focus:outline-none text-sm leading-relaxed disabled:opacity-50 transition-colors"
          />

          {/* Emoji Picker */}
          <Popover open={emojiOpen} onOpenChange={setEmojiOpen}>
            <PopoverTrigger asChild>
              <button
                id="emoji-btn"
                className="p-1.5 text-muted-foreground hover:text-foreground transition-all duration-200 hover:bg-secondary rounded-lg"
                aria-label="Ajouter un emoji"
              >
                <Smile size={18} />
              </button>
            </PopoverTrigger>
            <PopoverContent className="w-64 p-3 bg-card border border-border rounded-lg shadow-md">
              <div className="grid grid-cols-5 gap-2">
                {EMOJIS.map((emoji) => (
                  <button
                    key={emoji}
                    onClick={() => addEmoji(emoji)}
                    className="p-2 hover:bg-secondary rounded-lg transition-all duration-200 text-lg hover:scale-110 transform"
                  >
                    {emoji}
                  </button>
                ))}
              </div>
            </PopoverContent>
          </Popover>

          {/* Send Button */}
          <button
            onClick={handleSend}
            disabled={loading || !message.trim()}
            className="p-1.5 text-muted-foreground hover:text-primary disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-200 hover:bg-secondary rounded-lg flex items-center justify-center transform disabled:hover:scale-100"
            aria-label="Envoyer le message"
          >
            {loading ? (
              <Loader2 size={18} className="animate-spin" />
            ) : (
              <Send size={18} />
            )}
          </button>
        </div>

        {/* Image Generation Loading State */}
        {generatingImage && (
          <div className="flex items-center gap-3 px-4 py-3 mt-2 rounded-lg bg-gradient-to-r from-purple-600/20 to-purple-500/10 border border-purple-500/40 animate-pulse">
            <div className="flex gap-1">
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0s" }}
              />
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0.2s" }}
              />
              <div
                className="w-2 h-2 rounded-full bg-purple-400 animate-bounce"
                style={{ animationDelay: "0.4s" }}
              />
            </div>
            <span className="text-sm text-purple-300 font-medium">
              Génération d'image en cours...
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
