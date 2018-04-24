package me.limeice.common.function;


import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * IO处理工具
 * <pre>
 *     author: LimeVista(Lime)
 *     time  : 2018/03/15
 *     desc  : IO 工具类
 *     github: https://github.com/LimeVista/EasyCommon
 * </pre>
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public final class IOUtils {

    private IOUtils() {
        throw new UnsupportedOperationException("Don't instantiate...");
    }

    /**
     * 缓冲区大小
     */
    private static final int BUFFER_SIZE = 1024;

    /**
     * 从输入流中读取数据，并转换为Byte数组
     *
     * @param inStream 待操作的输入流
     * @return Byte数组形式的html文件
     * @throws IOException 各种异常，包括IOException
     */
    @NotNull
    public static byte[] read(@NotNull InputStream inStream) throws IOException {
        // 字节缓冲流
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        try {
            byte[] buffer = new byte[BUFFER_SIZE];
            int len;
            // 循环读取
            while ((len = inStream.read(buffer)) != -1)
                outStream.write(buffer, 0, len);
            return outStream.toByteArray();
        } finally {
            CloseUtils.closeIOQuietly(outStream);
        }
    }

    /**
     * 从输入流中读取数据，并转换为Byte数组
     *
     * @param file 文件
     * @return Byte数组形式的html文件
     * @throws IOException IOException
     */
    @NotNull
    public static byte[] read(@NotNull File file) throws IOException {
        FileInputStream in = null;
        FileChannel inChannel = null;
        try {
            in = new FileInputStream(file);
            inChannel = in.getChannel();
            ByteBuffer buffer = ByteBuffer.allocate((int) inChannel.size());
            inChannel.read(buffer);
            return buffer.array();
        } finally {
            CloseUtils.closeIOQuietly(in, inChannel);
        }
    }

    /**
     * 从输入流中读取数据，并转换为Byte数组
     *
     * @param filePath 文件路径
     * @return Byte数组形式的html文件
     * @throws IOException IOException
     */
    @NotNull
    public static byte[] read(@NotNull String filePath) throws IOException {
        return read(new File(filePath));
    }


    /**
     * 写入数据
     *
     * @param filePath 文件路径（如果存在覆盖，否则创建）
     * @param msg      文本（被写入数据）
     * @throws IOException IOException
     */
    public static void write(@NotNull String filePath, @NotNull String msg) throws IOException {
        write(new File(filePath), msg);
    }

    /**
     * 写入数据
     *
     * @param filePath 文件路径（如果存在覆盖，否则创建）
     * @param bytes    字节数据（被写入数据）
     * @throws IOException IOException
     */
    public static void write(@NotNull String filePath, @NotNull byte[] bytes) throws IOException {
        write(new File(filePath), bytes);
    }

    /**
     * 写入数据
     *
     * @param file 文件（如果存在覆盖，否则创建）
     * @param msg  文本（被写入数据）
     * @throws IOException IOException
     */
    public static void write(@NotNull File file, @NotNull String msg) throws IOException {
        checkFileIfNotExistCreate(file);
        FileWriter out = null;
        try {
            out = new FileWriter(file);
            out.write(msg);
            out.flush();
        } finally {
            CloseUtils.closeIOQuietly(out);
        }
    }

    /**
     * 写入数据
     *
     * @param file  文件（如果存在覆盖，否则创建）
     * @param bytes 字节数据（被写入数据）
     * @throws IOException IOException
     */
    public static void write(@NotNull File file, @NotNull byte[] bytes) throws IOException {
        checkFileIfNotExistCreate(file);
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            out.write(bytes);
            out.flush();
        } finally {
            CloseUtils.closeIOQuietly(out);
        }
    }

    /**
     * 写入数据
     *
     * @param file  文件（如果存在追加，否则创建）
     * @param bytes 字节数据（被写入数据）
     * @throws IOException IOException
     */
    public static void writeAppend(@NotNull File file, @NotNull byte[] bytes) throws IOException {
        checkFileIfNotExistCreate(file);
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file, true);
            out.write(bytes);
            out.flush();
        } finally {
            CloseUtils.closeIOQuietly(out);
        }
    }

    /**
     * 写入数据
     *
     * @param file   文件（如果存在覆盖，否则创建）
     * @param bytes  字节数据（被写入数据）
     * @param offset 偏移量
     * @param len    写入长度
     * @throws IOException IOException
     */
    public static void write(@NotNull File file, @NotNull byte[] bytes, int offset, int len) throws IOException {
        checkFileIfNotExistCreate(file);
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(file);
            out.write(bytes, offset, len);
            out.flush();
        } finally {
            CloseUtils.closeIOQuietly(out);
        }
    }

    /**
     * 检查文件是否存在，否则创建
     *
     * @param file 文件
     * @throws IOException IOException
     */
    public static void checkFileIfNotExistCreate(File file) throws IOException {
        if (!file.exists()) {
            if (!file.createNewFile())
                throw new IOException("Failure to create a file!File Path->" + file.getAbsolutePath());
        }
    }

    /**
     * 压缩文件
     *
     * @param input  输入流（源文件）
     * @param output 输出流（压缩文件）
     * @throws IOException IOE
     */
    public static void zip(@NotNull InputStream input, @NotNull OutputStream output) throws IOException {
        GZIPOutputStream gzip = null;
        try {
            gzip = new GZIPOutputStream(output);
            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = input.read(buf)) != -1) {
                gzip.write(buf, 0, len);
                gzip.flush();
            }
        } finally {
            CloseUtils.closeIOQuietly(input, gzip);
        }
    }

    /**
     * 解压文件
     *
     * @param input  输入流(压缩文件)
     * @param output 输出流（源文件）
     * @throws IOException IOE
     */
    public static void unzip(@NotNull InputStream input, @NotNull OutputStream output) throws IOException {
        GZIPInputStream gzip = null;
        try {
            gzip = new GZIPInputStream(input);
            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = gzip.read(buf)) != -1) {
                output.write(buf, 0, len);
            }
            output.flush();
        } finally {
            CloseUtils.closeIOQuietly(gzip, output);
        }
    }

    /**
     * 文件复制
     *
     * @param input  输入文件（被复制文件）
     * @param output 输出文件（复制文件）
     * @return 是否复制成功
     */
    public static boolean copyFile(@Nullable File input, @Nullable File output) {
        if (input == null || output == null)
            return false;
        FileChannel fileIn = null;
        FileChannel fileOut = null;
        try {
            fileIn = new FileInputStream(input).getChannel();
            fileOut = new FileOutputStream(output).getChannel();
            fileIn.transferTo(0, fileIn.size(), fileOut);
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } finally {
            CloseUtils.closeIOQuietly(fileIn, fileOut);
        }
    }

    /**
     * 移动文件
     *
     * @param input  输入文件
     * @param output 输出文件
     * @return 是否移动成功{@code true}成功否则失败
     */
    public static boolean moveFile(@Nullable File input, @Nullable File output) {
        return !(input == null || output == null) && input.exists() && input.renameTo(output);
    }
}