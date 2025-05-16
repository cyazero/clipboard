package org.example.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author cuiyao
 * Created on 2025/02/10
 */
@RestController
@RequestMapping("/api/clipboard")
public class ClipboardController {

    // 保存文件的目录
    private static final String SAVE_DIR = "temp_files";
    // 保存文件的创建时间
    private static final Map<String, Long> fileCreationTimes = new ConcurrentHashMap<>();
    // 新增白名单集合（存储文件绝对路径）
    private static final Set<String> whitelistedFiles = ConcurrentHashMap.newKeySet();
    // 定时任务执行器
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    // 最大文件总大小 1GB
    private static final long MAX_TOTAL_SIZE = (long) 1024 * 1024 * 1024;
    static {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                long currentTime = System.currentTimeMillis();
                List<String> filePaths = new ArrayList<>(fileCreationTimes.keySet());

                for (String filePath : filePaths) {
                    // 检查白名单
                    if (whitelistedFiles.contains(filePath)) {
                        continue;
                    }

                    Long creationTime = fileCreationTimes.get(filePath);
                    if (creationTime == null) continue;

                    if (currentTime - creationTime > 3 * 60 * 60 * 1000) {
                        File file = new File(filePath);
                        if (file.exists()) {
                            if (file.delete()) {
                                fileCreationTimes.remove(filePath);
                                whitelistedFiles.remove(filePath); // 清理无效白名单
                            }
                        } else {
                            fileCreationTimes.remove(filePath);
                            whitelistedFiles.remove(filePath);
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, 1, 1, TimeUnit.HOURS);
    }

    //添加/移除白名单
    @PutMapping("/whitelist/{fileName}")
    public ResponseEntity<String> manageWhitelist(
            @PathVariable String fileName,
            @RequestParam(defaultValue = "true") boolean addToWhitelist) {
        File targetFile = new File(SAVE_DIR, fileName);

        if (!targetFile.exists()) {
            return ResponseEntity.status(404).body("文件不存在");
        }

        String absolutePath = targetFile.getAbsolutePath();
        if (addToWhitelist) {
            whitelistedFiles.add(absolutePath);
        } else {
            whitelistedFiles.remove(absolutePath);
        }

        return ResponseEntity.ok("操作成功");
    }

    @PostMapping("/upload")
    public String handleUpload(@RequestParam(value = "text", required = false) String text,
                               @RequestPart(value = "file", required = false) MultipartFile file) {
        try {
            // 检查当前文件总大小
            long currentTotalSize = calculateTotalFileSize();
            if (text != null && !text.isEmpty()) {
                long textSize = text.getBytes().length;
                if (currentTotalSize + textSize > MAX_TOTAL_SIZE) {
                    return "上传失败，文件总大小将超过 1GB";
                }
                // 保存文字到文件
                String fileName = saveTextToFile(text);
                return "Saved successfully: " + fileName;
            } else if (file != null && !file.isEmpty()) {
                long fileSize = file.getSize();
                if (currentTotalSize + fileSize > MAX_TOTAL_SIZE) {
                    return "上传失败，文件总大小将超过 1GB";
                }
                // 保存上传的文件
                String fileName = saveUploadedFile(file);
                return "Saved successfully: " + fileName;
            } else {
                return "No text or file provided";
            }
        } catch (IOException e) {
            return "Error saving data: " + e.getMessage();
        }
    }
    private String saveTextToFile(String text) throws IOException {
        // 创建保存目录
        Path savePath = Paths.get(SAVE_DIR);
        if (!Files.exists(savePath)) {
            Files.createDirectories(savePath);
        }
        // 获取当前时间并格式化为字符串
        String timestamp = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
        String fileName = "text_" + timestamp + ".txt";
        File file = new File(savePath.toFile(), fileName);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(text.getBytes());
        }
        // 记录文件创建时间
        fileCreationTimes.put(file.getAbsolutePath(), System.currentTimeMillis());
        return fileName;
    }
    private String saveUploadedFile(MultipartFile file) throws IOException {
        String originalFileName = file.getOriginalFilename();
        Path savePath = Paths.get(SAVE_DIR);
        if (!Files.exists(savePath)) {
            Files.createDirectories(savePath);
        }
        assert originalFileName != null;
        File dest = new File(savePath.toFile(), originalFileName);
        if (dest.exists()) {
            int count = 1;
            String baseName = originalFileName.substring(0, originalFileName.lastIndexOf("."));
            String extension = originalFileName.substring(originalFileName.lastIndexOf("."));
            while (dest.exists()) {
                String newFileName = baseName + "_" + count + extension;
                dest = new File(savePath.toFile(), newFileName);
                count++;
            }
            originalFileName = dest.getName();
        }
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(file.getBytes());
        }
        // 记录文件创建时间
        fileCreationTimes.put(dest.getAbsolutePath(), System.currentTimeMillis());
        return originalFileName;
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
    public ResponseEntity<Resource> getFile(@PathVariable String fileName) {
        File file = new File(SAVE_DIR, fileName);
        if (file.exists() && file.isFile()) {
            Resource resource = new FileSystemResource(file);
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=" + fileName);
            String contentType = getContentType(file.toPath());
            return ResponseEntity.ok()
                    .headers(headers)
                    .contentType(MediaType.parseMediaType(contentType != null ? contentType : "application/octet-stream"))
                    .body(resource);
        }
        return ResponseEntity.notFound().build();
    }
    @DeleteMapping("/deleteFile/{fileName}")
    public String deleteFile(@PathVariable String fileName) {
        File file = new File(SAVE_DIR, fileName);
        if (file.exists() && file.isFile()) {
            if (file.delete()) {
                String absolutePath = file.getAbsolutePath();
                fileCreationTimes.remove(absolutePath);
                whitelistedFiles.remove(absolutePath);
                return "File deleted successfully";
            }
            return "Failed to delete file";
        }
        return "File not found";
    }

    private String getContentType(Path filePath) {
        try {
            return Files.probeContentType(filePath);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    private String getFileType(String contentType) {
        if (contentType == null) {
            return "file";
        }
        switch (contentType) {
            case "text/plain":
                return "text";
            case "image/jpeg":
            case "image/png":
            case "image/gif":
            case "image/bmp":
            case "image/webp":
                return "image";
            default:
                return "file";
        }
    }
    // 计算当前所有文件的总大小
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
