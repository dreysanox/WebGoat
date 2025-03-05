package org.owasp.webgoat.lessons.deserialization;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.io.InvalidClassException;
import java.util.HashSet;
import java.util.Set;

public class SecureObjectInputStream extends ObjectInputStream {
    private static final Set<String> allowedClasses = new HashSet<>();

    static {
        allowedClasses.add("org.dummy.insecure.framework.VulnerableTaskHolder");
        allowedClasses.add("java.lang.String");
        allowedClasses.add("java.time.LocalDateTime");
        allowedClasses.add("java.time.LocalDate");
        allowedClasses.add("java.time.LocalTime");
    }

    public SecureObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String className = desc.getName();
        if (!allowedClasses.contains(className)) {
            throw new InvalidClassException("Clase no autorizada: " + className);
        }
        return super.resolveClass(desc);
    }
}
