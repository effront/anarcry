package gg.effront.anarcry.fuzzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.NoSuchElementException;

public final class FilePayloadSource implements PayloadSource {

    private final Path path;
    private long lineCount = -1;

    public FilePayloadSource(Path path) {
        this.path = path;
    }

    @Override
    public long size() {
        if (lineCount < 0) {
            try (BufferedReader br = Files.newBufferedReader(path)) {
                long count = 0;
                while (br.readLine() != null) {
                    count++;
                }
                lineCount = count;
            } catch (IOException e) {
                lineCount = 0;
            }
        }
        return lineCount;
    }

    @Override
    public Iterator<String> iterator() {
        try {
            BufferedReader br = Files.newBufferedReader(path);
            return new Iterator<>() {
                private String next = advance();

                private String advance() {
                    try {
                        String line = br.readLine();
                        if (line == null) {
                            br.close();
                        }
                        return line;
                    } catch (IOException e) {
                        try {
                            br.close();
                        } catch (IOException ignored) {
                        }
                        return null;
                    }
                }

                @Override
                public boolean hasNext() {
                    return next != null;
                }

                @Override
                public String next() {
                    if (next == null) {
                        throw new NoSuchElementException();
                    }
                    String current = next;
                    next = advance();
                    return current;
                }
            };
        } catch (IOException e) {
            return java.util.Collections.emptyIterator();
        }
    }

    @Override
    public void reset() {
        // no-op; iterator() creates a new reader each time
    }

    @Override
    public String label() {
        return path.getFileName().toString() + " (" + String.format("%,d", size()) + " lines)";
    }

    public Path path() {
        return path;
    }

    public java.util.List<String> preview(int maxLines) {
        java.util.List<String> lines = new java.util.ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(path)) {
            String line;
            while ((line = br.readLine()) != null && lines.size() < maxLines) {
                lines.add(line);
            }
        } catch (IOException ignored) {
        }
        return lines;
    }
}
