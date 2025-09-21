package org.example.controller;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.spec.KeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/clipboard")
public class ClipboardController {

    private static final String SAVE_DIR = "temp_files";
    private static final String CHUNK_DIR = "file_chunks";
    private static final Map<String, Long> fileCreationTimes = new ConcurrentHashMap<>();
    private static final Set<String> whitelistedFiles = ConcurrentHashMap.newKeySet();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final long MAX_TOTAL_SIZE = (long) 1024 * 1024 * 1024;
    private static final Map<String, Set<Integer>> chunkStatus = new ConcurrentHashMap<>();

    @Value("${aes.secret.key:defaultSecretKey12345678901234567890}")
    private String serverAesKey;

    private static final byte[] PBKDF2_SALT = "FixedSaltValue123".getBytes();

    static {
        try {
            Files.createDirectories(Paths.get(SAVE_DIR));
            Files.createDirectories(Paths.get(CHUNK_DIR));
        } catch (IOException e) {
            e.printStackTrace();
        }

        scheduler.scheduleAtFixedRate(() -> {
            try {
                long currentTime = System.currentTimeMillis();
                List<String> filePaths = new ArrayList<>(fileCreationTimes.keySet());

                for (String filePath : filePaths) {
                    if (whitelistedFiles.contains(filePath)) continue;
                    Long creationTime = fileCreationTimes.get(filePath);
                    if (creationTime == null) continue;

                    if (currentTime - creationTime > 3 * 60 * 60 * 1000) {
                        File file = new File(filePath);
                        if (file.exists()) {
                            if (file.delete()) {
                                fileCreationTimes.remove(filePath);
                                whitelistedFiles.remove(filePath);
                            }
                        } else {
                            fileCreationTimes.remove(filePath);
                            whitelistedFiles.remove(filePath);
                        }
                    }
                }

                File chunkRoot = new File(CHUNK_DIR);
                if (chunkRoot.exists()) {
                    for (File sessionDir : Objects.requireNonNull(chunkRoot.listFiles())) {
                        if (System.currentTimeMillis() - sessionDir.lastModified() > 24 * 60 * 60 * 1000) {
                            FileUtils.deleteQuietly(sessionDir);
                            chunkStatus.remove(sessionDir.getName());
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    // 密钥派生函数
    private byte[] deriveKey(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), PBKDF2_SALT, 65536, 256);
        return factory.generateSecret(spec).getEncoded();
    }

    @PutMapping("/whitelist/{fileName}")
    public ResponseEntity<String> manageWhitelist(
            @PathVariable String fileName,
            @RequestParam(defaultValue = "true") boolean addToWhitelist) {
        File targetFile = new File(SAVE_DIR, fileName);
        if (!targetFile.exists()) return ResponseEntity.status(404).body("文件不存在");

        String absolutePath = targetFile.getAbsolutePath();
        if (addToWhitelist) {
            whitelistedFiles.add(absolutePath);
        } else {
            whitelistedFiles.remove(absolutePath);
        }

        return ResponseEntity.ok("操作成功");
    }

    @GetMapping("/checkChunks/{sessionId}")
    public ResponseEntity<Set<Integer>> checkChunks(@PathVariable String sessionId) {
        Path chunkPath = Paths.get(CHUNK_DIR, sessionId);
        if (!Files.exists(chunkPath)) return ResponseEntity.ok(Collections.emptySet());

        Set<Integer> uploadedChunks = new TreeSet<>();
        File[] chunks = chunkPath.toFile().listFiles();
        if (chunks != null) {
            for (File chunk : chunks) {
                try {
                    String name = chunk.getName();
                    if (name.endsWith(".chunk")) {
                        int index = Integer.parseInt(name.substring(0, name.indexOf('.')));
                        uploadedChunks.add(index);
                    }
                } catch (NumberFormatException ignored) {}
            }
        }
        return ResponseEntity.ok(uploadedChunks);
    }

    @PostMapping("/uploadChunk")
    public ResponseEntity<String> uploadChunk(
            @RequestParam("sessionId") String sessionId,
            @RequestParam("chunkIndex") int chunkIndex,
            @RequestParam("totalChunks") int totalChunks,
            @RequestParam("fileName") String fileName,
            @RequestPart("data") MultipartFile chunkData) {

        try {
            if (chunkData.getSize() > 50 * 1024 * 1024) {
                return ResponseEntity.badRequest().body("分片超过50MB限制");
            }

            byte[] encryptedData = chunkData.getBytes();

            byte[] iv = new byte[16];
            byte[] ciphertext;
            if (encryptedData.length >= 16) {
                iv = Arrays.copyOfRange(encryptedData, 0, 16);
                ciphertext = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
            } else {
                return ResponseEntity.badRequest().body("无效的分片数据");
            }

            byte[] decrypted = decrypt(ciphertext, serverAesKey, iv);

            Path chunkPath = Paths.get(CHUNK_DIR, sessionId);
            Files.createDirectories(chunkPath);
            Path chunkFile = chunkPath.resolve(chunkIndex + ".chunk");
            Files.write(chunkFile, decrypted);

            chunkStatus.computeIfAbsent(sessionId, k -> new HashSet<>()).add(chunkIndex);

            if (isUploadComplete(chunkPath, totalChunks)) {
                try {
                    mergeFile(chunkPath, fileName);
                    return ResponseEntity.ok("文件上传完成: " + fileName);
                } catch (NoSuchFileException e) {
                    return ResponseEntity.ok("文件已被合并");
                }
            }

            return ResponseEntity.ok("分片接收成功");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("分片处理失败: " + e.getMessage());
        }
    }

    @PostMapping("/uploadText")
    public ResponseEntity<String> uploadText(
            @RequestParam("text") String text) {

        try {
            long currentTotalSize = calculateTotalFileSize();
            long textSize = text.getBytes().length;
            if (currentTotalSize + textSize > MAX_TOTAL_SIZE) {
                return ResponseEntity.badRequest().body("上传失败，文件总大小将超过 1GB");
            }

            byte[] encryptedData = Base64.getDecoder().decode(text);
            byte[] iv = new byte[16];
            byte[] ciphertext;

            if (encryptedData.length >= 16) {
                iv = Arrays.copyOfRange(encryptedData, 0, 16);
                ciphertext = Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
            } else {
                return ResponseEntity.badRequest().body("无效的文本数据");
            }

            byte[] decrypted = decrypt(ciphertext, serverAesKey, iv);
            String decryptedText = new String(decrypted);

            String fileName = saveTextToFile(decryptedText);
            return ResponseEntity.ok("Saved successfully: " + fileName);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("文本处理失败: " + e.getMessage());
        }
    }

    private byte[] decrypt(byte[] ciphertext, String key, byte[] iv) throws Exception {
        byte[] keyBytes = deriveKey(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(ciphertext);
    }

    private boolean isUploadComplete(Path chunkPath, int totalChunks) {
        Set<Integer> uploaded = new HashSet<>();
        File[] files = chunkPath.toFile().listFiles();
        if (files == null) return false;

        for (File file : files) {
            String name = file.getName();
            if (name.endsWith(".chunk")) {
                try {
                    int index = Integer.parseInt(name.substring(0, name.indexOf('.')));
                    if (index >= 0 && index < totalChunks) {
                        uploaded.add(index);
                    }
                } catch (NumberFormatException ignored) {}
            }
        }
        return uploaded.size() == totalChunks;
    }

    private synchronized void mergeFile(Path chunkPath, String fileName) throws IOException {
        // 检查是否已被其他线程合并
        if (!Files.exists(chunkPath)) {
            return;
        }

        Path tempFile = Files.createTempFile("merge_", ".tmp");
        try (OutputStream os = Files.newOutputStream(tempFile, StandardOpenOption.CREATE)) {
            File[] chunkFiles = chunkPath.toFile().listFiles();
            if (chunkFiles != null) {
                Arrays.sort(chunkFiles, Comparator.comparingInt(f -> {
                    try {
                        return Integer.parseInt(f.getName().split("\\.")[0]);
                    } catch (NumberFormatException e) {
                        return Integer.MAX_VALUE;
                    }
                }));

                for (File chunk : chunkFiles) {
                    Files.copy(chunk.toPath(), os);
                }
            }
        }

        Path targetFile = getUniqueFilePath(Paths.get(SAVE_DIR), fileName);
        Files.move(tempFile, targetFile);

        fileCreationTimes.put(targetFile.toAbsolutePath().toString(), System.currentTimeMillis());

        FileUtils.deleteDirectory(chunkPath.toFile());
        chunkStatus.remove(chunkPath.getFileName().toString());
    }

    private Path getUniqueFilePath(Path dir, String fileName) {
        Path target = dir.resolve(fileName);
        if (!Files.exists(target)) return target;

        String baseName = fileName.substring(0, fileName.lastIndexOf('.'));
        String extension = fileName.substring(fileName.lastIndexOf('.'));
        int count = 1;

        while (true) {
            String newFileName = baseName + "(" + count + ")" + extension;
            Path newPath = dir.resolve(newFileName);
            if (!Files.exists(newPath)) return newPath;
            count++;
        }
    }

    @GetMapping("/queryAllFiles")
    public List<Map<String, Object>> queryAllFiles() {
        List<Map<String, Object>> fileList = new ArrayList<>();
        File saveDir = new File(SAVE_DIR);
        if (saveDir.exists() && saveDir.isDirectory()) {
            File[] files = saveDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    Map<String, Object> fileInfo = new HashMap<>();
                    String absolutePath = file.getAbsolutePath();
                    fileInfo.put("fileName", file.getName());
                    fileInfo.put("creationTime", new Date(file.lastModified()));
                    String contentType = getContentType(file.toPath());
                    fileInfo.put("type", getFileType(contentType));
                    fileInfo.put("isWhitelisted", whitelistedFiles.contains(absolutePath));
                    fileList.add(fileInfo);
                }
            }
        }
        return fileList;
    }

    @GetMapping("/files/{fileName}")
    public ResponseEntity<byte[]> getFile(@PathVariable String fileName) {
        try {
            File file = new File(SAVE_DIR, fileName);
            if (!file.exists() || !file.isFile()) return ResponseEntity.notFound().build();

            byte[] fileContent = Files.readAllBytes(file.toPath());

            byte[] iv = new byte[16];
            new Random().nextBytes(iv);

            byte[] encrypted = encrypt(fileContent, serverAesKey, iv);

            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=" + fileName);
            String contentType = getContentType(file.toPath());

            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.parseMediaType(contentType != null ? contentType : "application/octet-stream"))
                    .body(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    // 新增文本下载接口
    @GetMapping("/downloadText/{fileName}")
    public ResponseEntity<byte[]> downloadTextFile(@PathVariable String fileName) {
        try {
            File file = new File(SAVE_DIR, fileName);
            if (!file.exists() || !file.isFile()) return ResponseEntity.notFound().build();

            byte[] fileContent = Files.readAllBytes(file.toPath());

            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + fileName);
            headers.add(HttpHeaders.CONTENT_TYPE, "text/plain");

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(fileContent);
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    private byte[] encrypt(byte[] data, String key, byte[] iv) throws Exception {
        byte[] keyBytes = deriveKey(key);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
        return cipher.doFinal(data);
    }

    @DeleteMapping("/deleteFile/{fileName}")
    public ResponseEntity<String> deleteFile(@PathVariable String fileName) {
        File file = new File(SAVE_DIR, fileName);
        if (file.exists() && file.isFile()) {
            if (file.delete()) {
                String absolutePath = file.getAbsolutePath();
                fileCreationTimes.remove(absolutePath);
                whitelistedFiles.remove(absolutePath);
                return ResponseEntity.ok("文件删除成功");
            }
            return ResponseEntity.status(500).body("删除文件失败");
        }
        return ResponseEntity.status(404).body("文件不存在");
    }

    private String saveTextToFile(String text) throws IOException {
        Path savePath = Paths.get(SAVE_DIR);
        if (!Files.exists(savePath)) Files.createDirectories(savePath);

        String timestamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
        String fileName = "text_" + timestamp + ".txt";
        File file = getUniqueFilePath(savePath, fileName).toFile();

        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(text.getBytes());
        }
        fileCreationTimes.put(file.getAbsolutePath(), System.currentTimeMillis());
        return file.getName();
    }

    private String getContentType(Path filePath) {
        try {
            return Files.probeContentType(filePath);
        } catch (IOException e) {
            return null;
        }
    }

    private String getFileType(String contentType) {
        if (contentType == null) return "file";
        switch (contentType) {
            case "text/plain": return "text";
            case "image/jpeg":
            case "image/png":
            case "image/gif":
            case "image/bmp":
            case "image/webp": return "image";
            default: return "file";
        }
    }

    private long calculateTotalFileSize() {
        long totalSize = 0;
        File saveDir = new File(SAVE_DIR);
        if (saveDir.exists() && saveDir.isDirectory()) {
            File[] files = saveDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    totalSize += file.length();
                }
            }
        }
        return totalSize;
    }
}