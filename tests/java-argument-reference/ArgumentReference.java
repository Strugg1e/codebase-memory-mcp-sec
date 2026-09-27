package sample;

// Trusted fixture driver. Never used as audited-project input.
public final class ArgumentReference {
    public static void main(String[] args) {
        Service service = new Service();
        service.recorder = new Recorder();
        service.external = new External();
        Facade facade = new Facade();
        facade.service = service;
        Entry entry = new Entry();
        entry.facade = facade;
        long[][] inputs = {{10, 100}, {11, 100}, {10, 101}, {-1, 100}, {-1, 101}};
        for (long[] input : inputs) {
            System.out.println(entry.handle(input[0], input[1]));
        }
    }
}

final class Recorder {
    long store(long id, long tenant) { return tenant; }
}

final class External {
    long value() { return 777; }
}
