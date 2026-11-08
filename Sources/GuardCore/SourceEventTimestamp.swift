import Foundation

/// Optional source timestamps, never inferred from process birth, receive time, or a monotonic clock.
/// Only ordinary RFC3339 dates with at most nine fractional digits are supported. Unknown shapes,
/// invalid calendar values, and leap-second representations remain unrecorded.
public enum SourceEventTimestamp {
    public static func parse(_ value: Any?) -> Date? {
        guard let text = value as? String else { return nil }
        return parseString(text, unifiedLog: false)
    }

    /// `log stream --style ndjson` also uses a space separator and a compact numeric UTC offset.
    public static func parseUnifiedLog(_ value: Any?) -> Date? {
        guard let text = value as? String else { return nil }
        return parseString(text, unifiedLog: true)
    }

    private static func parseString(_ text: String, unifiedLog: Bool) -> Date? {
        // Bound the temporary byte array as well as the accepted timestamp precision.
        guard (20...35).contains(text.utf8.count) else { return nil }
        let bytes = Array(text.utf8)
        guard bytes[4] == 45, bytes[7] == 45, bytes[13] == 58, bytes[16] == 58,
              bytes[10] == 84 || bytes[10] == 116 || (unifiedLog && bytes[10] == 32),
              let year = digits(bytes, 0..<4), year > 0,
              let month = digits(bytes, 5..<7), (1...12).contains(month),
              let day = digits(bytes, 8..<10),
              let hour = digits(bytes, 11..<13), hour < 24,
              let minute = digits(bytes, 14..<16), minute < 60,
              let second = digits(bytes, 17..<19), second < 60 else { return nil }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        let days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard (1...days[month - 1]).contains(day) else { return nil }

        var position = 19
        var fraction = 0
        var scale = 1
        if bytes[position] == 46 {
            position += 1
            let start = position
            while position < bytes.count, (48...57).contains(bytes[position]) {
                guard position - start < 9 else { return nil }
                fraction = fraction * 10 + Int(bytes[position] - 48)
                scale *= 10
                position += 1
            }
            guard position > start else { return nil }
        }
        guard position < bytes.count else { return nil }
        let offset: Int
        if bytes[position] == 90 || bytes[position] == 122 {
            guard position + 1 == bytes.count else { return nil }
            offset = 0
        } else {
            guard bytes[position] == 43 || bytes[position] == 45 else { return nil }
            let remaining = bytes.count - position
            let minutePosition: Int
            if remaining == 6, bytes[position + 3] == 58 {
                minutePosition = position + 4
            } else if unifiedLog, remaining == 5 {
                minutePosition = position + 3
            } else {
                return nil
            }
            guard let hours = digits(bytes, (position + 1)..<(position + 3)), hours < 24,
                  let minutes = digits(bytes, minutePosition..<(minutePosition + 2)), minutes < 60 else { return nil }
            offset = (bytes[position] == 43 ? 1 : -1) * (hours * 3_600 + minutes * 60)
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let components = DateComponents(era: 1, year: year, month: month, day: day,
                                        hour: hour, minute: minute, second: second)
        guard let whole = calendar.date(from: components) else { return nil }
        // A calendar must not silently normalize an unsupported historical date.
        let decoded = calendar.dateComponents([.era, .year, .month, .day, .hour, .minute, .second], from: whole)
        guard decoded.era == 1, decoded.year == year, decoded.month == month, decoded.day == day,
              decoded.hour == hour, decoded.minute == minute, decoded.second == second else { return nil }
        // Parse the whole second separately so Foundation formatters cannot truncate the fraction.
        return whole.addingTimeInterval(Double(fraction) / Double(scale) - Double(offset))
    }

    private static func digits(_ bytes: [UInt8], _ range: Range<Int>) -> Int? {
        var value = 0
        for index in range {
            guard (48...57).contains(bytes[index]) else { return nil }
            value = value * 10 + Int(bytes[index] - 48)
        }
        return value
    }
}
