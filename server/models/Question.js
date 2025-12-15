const mongoose = require('mongoose');

const questionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    question: {
        type: String,
        required: true,
        trim: true
    },
    category: {
        type: String,
        enum: ['belief', 'worship', 'comparison', 'general', 'ethics', 'history'],
        required: true
    },
    answer: {
        text: String,
        answeredBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User'
        },
        answeredAt: Date,
        references: [String]
    },
    status: {
        type: String,
        enum: ['pending', 'answered', 'rejected'],
        default: 'pending'
    },
    isPublic: {
        type: Boolean,
        default: true
    },
    views: {
        type: Number,
        default: 0
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Question', questionSchema);
