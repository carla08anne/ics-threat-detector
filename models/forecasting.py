import pandas as pd
import numpy as np
from collections import defaultdict
import json

# ── ATTACK TRANSITION MATRIX ──────────────────────────
# Based on real ICS attack kill chain patterns
# Shows probability of attack B following attack A

TRANSITION_MATRIX = {
    'NORMAL': {
        'NORMAL'             : 0.70,
        'UNAUTHORIZED_ACCESS': 0.15,
        'DDoS'               : 0.08,
        'SPOOFING'           : 0.04,
        'COMMAND_INJECTION'  : 0.03,
    },
    'UNAUTHORIZED_ACCESS': {
        'NORMAL'             : 0.20,
        'UNAUTHORIZED_ACCESS': 0.25,
        'COMMAND_INJECTION'  : 0.30,  # most likely next step
        'SPOOFING'           : 0.15,
        'DDoS'               : 0.10,
    },
    'DDoS': {
        'NORMAL'             : 0.15,
        'DDoS'               : 0.45,  # floods continue
        'COMMAND_INJECTION'  : 0.20,
        'UNAUTHORIZED_ACCESS': 0.12,
        'SPOOFING'           : 0.08,
    },
    'SPOOFING': {
        'NORMAL'             : 0.10,
        'COMMAND_INJECTION'  : 0.45,  # spoofing leads to injection
        'SPOOFING'           : 0.25,
        'DDoS'               : 0.12,
        'UNAUTHORIZED_ACCESS': 0.08,
    },
    'COMMAND_INJECTION': {
        'NORMAL'             : 0.10,
        'COMMAND_INJECTION'  : 0.40,  # injection continues
        'SPOOFING'           : 0.25,
        'DDoS'               : 0.15,
        'UNAUTHORIZED_ACCESS': 0.10,
    },
}

# ── ATTACK SEVERITY ───────────────────────────────────
SEVERITY = {
    'NORMAL'             : 0,
    'UNAUTHORIZED_ACCESS': 2,
    'DDoS'               : 3,
    'SPOOFING'           : 4,
    'COMMAND_INJECTION'  : 5,
}

MITRE_MAP = {
    'DDoS'               : 'T0814',
    'SPOOFING'           : 'T0831',
    'COMMAND_INJECTION'  : 'T0836',
    'UNAUTHORIZED_ACCESS': 'T0801',
    'NORMAL'             : 'N/A',
}


class AttackForecaster:
    """
    Predicts next likely attack based on current
    attack sequence using Markov Chain model.
    """

    def __init__(self, window_size=5):
        self.window_size    = window_size
        self.attack_history = []
        self.predictions    = []

    def update(self, attack_type):
        """Add new attack to history and generate forecast."""
        self.attack_history.append(attack_type)

        # Keep only recent history
        if len(self.attack_history) > 50:
            self.attack_history.pop(0)

        return self.forecast()

    def forecast(self):
        """Generate next attack prediction."""
        if not self.attack_history:
            return None

        current = self.attack_history[-1]
        transitions = TRANSITION_MATRIX.get(
            current, TRANSITION_MATRIX['NORMAL'])

        # Get probabilities for each next attack
        predictions = []
        for next_attack, prob in transitions.items():
            if next_attack == 'NORMAL':
                continue

            # Boost probability if we've seen this pattern before
            boost = self._calculate_boost(current, next_attack)
            adjusted_prob = min(prob + boost, 0.95)

            predictions.append({
                'attack_type'   : next_attack,
                'probability'   : round(adjusted_prob * 100, 1),
                'mitre_id'      : MITRE_MAP[next_attack],
                'severity_score': SEVERITY[next_attack],
                'risk_level'    : self._risk_level(adjusted_prob),
            })

        # Sort by probability
        predictions.sort(key=lambda x: x['probability'], reverse=True)

        # Overall threat level
        top_prob = predictions[0]['probability'] if predictions else 0
        threat_escalating = self._is_escalating()

        return {
            'current_attack'    : current,
            'predictions'       : predictions[:3],  # top 3
            'top_prediction'    : predictions[0] if predictions else None,
            'threat_escalating' : threat_escalating,
            'attack_sequence'   : self.attack_history[-5:],
            'recommendation'    : self._get_recommendation(
                predictions[0] if predictions else None,
                threat_escalating
            ),
        }

    def _calculate_boost(self, current, next_attack):
        """Boost probability if pattern seen before in history."""
        if len(self.attack_history) < 2:
            return 0

        count = 0
        for i in range(len(self.attack_history) - 1):
            if (self.attack_history[i] == current and
                    self.attack_history[i+1] == next_attack):
                count += 1

        return min(count * 0.05, 0.2)

    def _is_escalating(self):
        """Check if attack severity is increasing."""
        if len(self.attack_history) < 3:
            return False

        recent = self.attack_history[-3:]
        scores = [SEVERITY.get(a, 0) for a in recent]
        return scores[-1] > scores[0]

    def _risk_level(self, prob):
        if prob > 0.7:  return 'CRITICAL'
        if prob > 0.5:  return 'HIGH'
        if prob > 0.3:  return 'MEDIUM'
        return 'LOW'

    def _get_recommendation(self, top_pred, escalating):
        """Generate proactive recommendation."""
        if not top_pred:
            return "Monitor network — no immediate threat predicted"

        attack = top_pred['attack_type']
        prob   = top_pred['probability']

        recs = {
            'COMMAND_INJECTION'  : f"Pre-emptively restrict write access to PLCs — {prob}% injection probability",
            'DDoS'               : f"Enable rate limiting now — {prob}% DDoS probability detected",
            'SPOOFING'           : f"Verify IP-MAC bindings immediately — {prob}% spoofing probability",
            'UNAUTHORIZED_ACCESS': f"Strengthen authentication — {prob}% unauthorized access probability",
        }

        base = recs.get(attack, f"Monitor closely — {prob}% threat probability")

        if escalating:
            base += " ⚠️ THREAT IS ESCALATING"

        return base


# ── TEST ──────────────────────────────────────────────
if __name__ == '__main__':
    forecaster = AttackForecaster()

    print("🔮 ATTACK FORECASTING ENGINE — TEST")
    print("=" * 60)

    # Simulate a realistic attack sequence
    sequence = [
        'NORMAL',
        'NORMAL',
        'UNAUTHORIZED_ACCESS',
        'UNAUTHORIZED_ACCESS',
        'COMMAND_INJECTION',
        'SPOOFING',
        'COMMAND_INJECTION',
    ]

    for attack in sequence:
        result = forecaster.update(attack)
        print(f"\nCurrent  : {attack}")
        print(f"Sequence : {' → '.join(result['attack_sequence'])}")
        print(f"Escalating: {'YES ⚠️' if result['threat_escalating'] else 'No'}")
        print(f"\nNext Attack Predictions:")
        for pred in result['predictions']:
            bar = '█' * int(pred['probability'] / 5)
            print(f"  {pred['attack_type']:<25} {bar} {pred['probability']}% "
                  f"({pred['risk_level']})")
        print(f"\n💡 {result['recommendation']}")
        print("-" * 60)