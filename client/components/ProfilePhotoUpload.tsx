import { useState, useRef } from "react";
import { Upload, X, Loader2, Check } from "lucide-react";
import { getStorage, ref, uploadBytes, getDownloadURL } from "firebase/storage";
import { doc, updateDoc } from "firebase/firestore";
import { db } from "@/lib/firebase";
import { toast } from "sonner";

interface ProfilePhotoUploadProps {
  userId: string;
  currentPhotoUrl?: string;
  displayName: string;
  onPhotoUpdate?: (photoUrl: string) => void;
}

export function ProfilePhotoUpload({
  userId,
  currentPhotoUrl,
  displayName,
  onPhotoUpdate,
}: ProfilePhotoUploadProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<string | null>(
    currentPhotoUrl || null,
  );
  const [uploading, setUploading] = useState(false);

  const handleFileSelect = async (
    event: React.ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith("image/")) {
      toast.error("Veuillez sélectionner une image");
      return;
    }

    // Validate file size (max 5MB for free tier)
    const maxSize = 5 * 1024 * 1024; // 5MB
    if (file.size > maxSize) {
      toast.error("L'image doit faire moins de 5MB");
      return;
    }

    try {
      setUploading(true);

      // Create preview
      const reader = new FileReader();
      reader.onload = async (e) => {
        const previewUrl = e.target?.result as string;
        setPreview(previewUrl);

        // Upload to Firebase Storage
        try {
          const storage = getStorage();
          const storageRef = ref(
            storage,
            `profile-photos/${userId}/${Date.now()}_${file.name}`,
          );

          // Upload the file
          await uploadBytes(storageRef, file);

          // Get the download URL
          const downloadUrl = await getDownloadURL(storageRef);

          // Update user document in Firestore
          const userRef = doc(db, "users", userId);
          await updateDoc(userRef, {
            profilePhotoURL: downloadUrl,
          });

          setPreview(downloadUrl);
          onPhotoUpdate?.(downloadUrl);
          toast.success("Photo de profil mise à jour!");
        } catch (uploadError) {
          console.error("Upload error:", uploadError);
          toast.error("Erreur lors du téléchargement");
          setPreview(currentPhotoUrl || null);
        } finally {
          setUploading(false);
        }
      };
      reader.readAsDataURL(file);
    } catch (error) {
      console.error("Error processing file:", error);
      toast.error("Erreur lors du traitement du fichier");
      setUploading(false);
    }
  };

  const handleRemovePhoto = async () => {
    try {
      setLoading(true);
      const userRef = doc(db, "users", userId);
      await updateDoc(userRef, {
        profilePhotoURL: "",
      });
      setPreview(null);
      onPhotoUpdate?.("");
      toast.success("Photo de profil supprimée");
    } catch (error) {
      console.error("Error removing photo:", error);
      toast.error("Erreur lors de la suppression");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2.5">
      <div className="flex items-end gap-3">
        {/* Photo Preview */}
        <div className="relative">
          <div className="w-16 h-16 rounded-full overflow-hidden border-2 border-primary/30 bg-gradient-to-br from-primary/40 to-primary/50 flex items-center justify-center flex-shrink-0">
            {preview ? (
              <img
                src={preview}
                alt="Profile"
                className="w-full h-full object-cover"
              />
            ) : (
              <span className="text-2xl font-bold text-white">
                {displayName?.[0]?.toUpperCase() || "U"}
              </span>
            )}
          </div>

          {/* Remove Photo Button */}
          {preview && !uploading && (
            <button
              onClick={handleRemovePhoto}
              disabled={loading}
              className="absolute -top-2 -right-2 w-6 h-6 rounded-full bg-red-500 hover:bg-red-600 flex items-center justify-center text-white transition-colors disabled:opacity-50"
              title="Supprimer la photo"
            >
              {loading ? (
                <Loader2 size={14} className="animate-spin" />
              ) : (
                <X size={14} />
              )}
            </button>
          )}

          {/* Uploading Indicator */}
          {uploading && (
            <div className="absolute inset-0 rounded-full bg-black/50 flex items-center justify-center">
              <Loader2 size={20} className="animate-spin text-white" />
            </div>
          )}
        </div>

        {/* Upload Button */}
        <div className="flex-1">
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading || loading}
            className="w-full px-3 py-2 rounded-[10px] border border-white/[0.1] hover:border-white/[0.2] bg-white/[0.03] hover:bg-white/[0.06] text-foreground/80 hover:text-foreground disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 font-medium text-xs"
          >
            {uploading ? (
              <>
                <Loader2 size={14} className="animate-spin" />
                <span className="hidden sm:inline">Téléchargement...</span>
              </>
            ) : preview ? (
              <>
                <Upload size={14} />
                <span>Changer</span>
              </>
            ) : (
              <>
                <Upload size={14} />
                <span>Télécharger</span>
              </>
            )}
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleFileSelect}
            disabled={uploading || loading}
            className="hidden"
            aria-label="Sélectionner une photo de profil"
          />
          <p className="text-xs text-foreground/40 mt-1.5">Max 5MB</p>
        </div>
      </div>
    </div>
  );
}
