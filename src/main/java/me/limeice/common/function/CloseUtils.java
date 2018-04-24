package me.limeice.common.function;

import java.io.Closeable;
import java.io.IOException;

/**
 * 根据作者（Blankj）开源项目修改，致敬作者<a href="https://github.com/Blankj/AndroidUtilCode">Github Page</>
 * <pre>
 *     author: LimeVista(Lime)
 *     time  : 2018/03/12
 *     desc  : 关闭相关工具类
 *     github: https://github.com/LimeVista/EasyCommon
 * </pre>
 */
public final class CloseUtils {

    private CloseUtils() {
        throw new UnsupportedOperationException("Don't instantiate...");
    }

    /**
     * 关闭IO
     *
     * @param closeables closeables
     */
    public static void closeIO(final Closeable... closeables) {
        if (closeables == null) return;
        for (Closeable closeable : closeables) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 关闭IO(静默操作)
     *
     * @param closeables closeables
     */
    public static void closeIOQuietly(final Closeable... closeables) {
        if (closeables == null) return;
        for (Closeable closeable : closeables) {
            if (closeable != null) {
                try {
                    closeable.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * 关闭IO(静默操作)
     *
     * @param closeable closeable
     */
    public static void closeIOQuietly(final Closeable closeable) {
        if (closeable == null) return;
        try {
            closeable.close();
        } catch (IOException ignored) {
        }
    }
}