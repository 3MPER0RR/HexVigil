use std::env;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use goblin::Object;

fn main() {
    let args: Vec<String> = env::args().collect();

    let target = if args.len() > 1 {
        &args[1]
    } else {
        "."
    };

    println!("🔍 Analizzando target: {}\n", target);

    let path = Path::new(target);

    if path.is_file() {
        analyze_single_file(target);
    } else if path.is_dir() {
        analyze_directory(target);
    } else {
        println!("❌ Percorso non valido.");
    }
}

// ---------------------------------------------

fn analyze_directory(dir: &str) {
    let mut count = 0;

    for entry in WalkDir::new(dir).max_depth(5) {
        if let Ok(e) = entry {
            let p = e.path();

            if p.is_file() {
                count += 1;
                analyze_single_file(p.to_str().unwrap());
            }
        }
    }

    println!("\n📁 Analisi completata su {} file.", count);
}

// ---------------------------------------------

fn analyze_single_file(path: &str) {
    println!("\n📄 Analizzando: {}", path);

    if path.ends_with(".c") || path.ends_with(".h") {
        println!("Tipo: Sorgente C");
        analyze_c_source(path);

    } else if path.ends_with(".rs") {
        println!("Tipo: Sorgente Rust (analisi base)");
        analyze_rust_source(path);

    } else {
        analyze_binary(path);
    }
}

// ---------------------------------------------

fn analyze_c_source(path: &str) {
    println!("⚙️ Analisi codice C avanzata...");

    let content = fs::read_to_string(path).unwrap_or_default();

    let dangerous_patterns = vec![
        ("gets(", "CRITICO", "Buffer Overflow",
         "gets() non controlla la lunghezza dell'input",
         "Usare fgets(buffer, size, stdin)"),

        ("strcpy(", "CRITICO", "Buffer Overflow",
         "strcpy non verifica la dimensione del buffer",
         "Sostituire con strncpy o strlcpy"),

        ("strcat(", "ALTO", "Buffer Overflow",
         "strcat può causare overflow",
         "Usare strncat"),

        ("sprintf(", "ALTO", "Format String / Overflow",
         "sprintf non limita la lunghezza",
         "Usare snprintf"),

        ("system(", "MEDIO", "Command Injection",
         "Esecuzione comandi esterni non validati",
         "Validare input o evitare system()"),

        ("scanf(", "MEDIO", "Input non sicuro",
         "scanf senza limitazioni è pericoloso",
         "Usare scanf con limiti o fgets"),

        ("malloc(", "INFO", "Gestione memoria",
         "Allocazione memoria senza controllo",
         "Verificare sempre il valore di ritorno"),

        ("free(", "INFO", "Gestione memoria",
         "Possibile double free o use-after-free",
         "Assicurarsi che il puntatore sia valido")
    ];

    let mut trovate = 0;

    for (i, line) in content.lines().enumerate() {
        for (pattern, severity, category, desc, fix) in &dangerous_patterns {
            if line.contains(pattern) {
                trovate += 1;

                println!("\n--------------------------------------");
                println!("⚠ Vulnerabilità individuata!");
                println!("Riga: {}", i + 1);
                println!("Codice: {}", line.trim());
                println!("Severità: {}", severity);
                println!("Categoria: {}", category);
                println!("Dettaglio: {}", desc);
                println!("Rimedio: {}", fix);
            }
        }
    }

    println!("\n🔎 Analisi completata: {} potenziali problemi trovati.", trovate);

    if trovate == 0 {
        println!("✅ Nessuna funzione pericolosa individuata.");
    }
}

// ---------------------------------------------

fn analyze_rust_source(path: &str) {
    let content = fs::read_to_string(path).unwrap_or_default();

    if content.contains("unsafe") {
        println!("⚠ Trovato blocco unsafe: possibile rischio memoria");
    }

    if content.contains("unwrap()") {
        println!("⚠ Uso di unwrap(): possibile crash non gestito");
    }

    println!("ℹ Analisi Rust base completata.");
}

// ---------------------------------------------

fn analyze_binary(path: &str) {
    println!("🔧 Analisi eseguibile binario...");

    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => {
            println!("❌ Impossibile leggere il file.");
            return;
        }
    };

    match Object::parse(&data) {
        Ok(Object::Elf(elf)) => {
            println!("🧩 Tipo: ELF (Linux)");

            if elf.libraries.is_empty() {
                println!("⚠ Binario statico o senza import: possibile file sospetto");
            }

            for lib in elf.libraries {
                println!("📦 Dipendenza: {}", lib);
            }
        }

        Ok(Object::PE(pe)) => {
            println!("🧩 Tipo: PE (Windows)");

            for import in pe.imports {
                println!("🔗 Import: {}", import.name);
            }
        }

        Ok(Object::Mach(mach)) => {
            println!("🧩 Tipo: Mach-O (macOS)");
            println!("ℹ Architettura: {:?}", mach);
        }

        _ => {
            println!("❓ Formato non riconosciuto o non supportato.");
        }
    }
}